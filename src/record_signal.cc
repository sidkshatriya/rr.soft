/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "record_signal.h"

#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/user.h>
#include <syscall.h>

#include "AddressSpace.h"
#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "Flags.h"
#include "PerfCounters.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "TraceStream.h"
#include "VirtualPerfCounterMonitor.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

static void restore_sighandler_if_not_default(RecordTask* t, int sig) {
  if (t->sig_disposition(sig) != SIGNAL_DEFAULT) {
    LOG(debug) << "Restoring signal handler for " << signal_name(sig);
    AutoRemoteSyscalls remote(t);
    size_t sigset_size = sigaction_sigset_size(remote.arch());
    const vector<uint8_t>& sa = t->signal_action(sig);
    AutoRestoreMem child_sa(remote, sa.data(), sa.size());
    remote.infallible_syscall(syscall_number_for_rt_sigaction(remote.arch()),
                              sig, child_sa.get().as_int(), nullptr,
                              sigset_size);
  }
}

/**
 * Restore the blocked-ness and sigaction for |sig| from |t|'s local
 * copy.
 */
static void restore_signal_state(RecordTask* t, int sig,
                                 SignalBlocked signal_was_blocked) {
  restore_sighandler_if_not_default(t, sig);
  if (signal_was_blocked) {
    LOG(debug) << "Restoring signal blocked-ness for " << signal_name(sig);
    AutoRemoteSyscalls remote(t);
    size_t sigset_size = sigaction_sigset_size(remote.arch());
    vector<uint8_t> bytes;
    bytes.resize(sigset_size);
    memset(bytes.data(), 0, sigset_size);
    sig_set_t mask = signal_bit(sig);
    ASSERT(t, sigset_size >= sizeof(mask));
    memcpy(bytes.data(), &mask, sizeof(mask));
    AutoRestoreMem child_block(remote, bytes.data(), bytes.size());
    remote.infallible_syscall(syscall_number_for_rt_sigprocmask(remote.arch()),
                              SIG_BLOCK, child_block.get().as_int(), nullptr,
                              sigset_size);
    // We just changed the sigmask ourselves.
    t->invalidate_sigmask();
  }
}

/**
 * Return true if |t| was stopped because of a SIGSEGV resulting
 * from a disabled instruction and |t| was updated appropriately, false
 * otherwise.
 */
static bool try_handle_trapped_instruction(RecordTask* t, siginfo_t* si) {
  ASSERT(t, si->si_signo == SIGSEGV);

  auto special_instruction = special_instruction_at(t, t->ip());
  switch (special_instruction.opcode) {
    case SpecialInstOpcode::ARM_MRS_CNTFRQ_EL0:
    case SpecialInstOpcode::ARM_MRS_CNTVCT_EL0:
    case SpecialInstOpcode::ARM_MRS_CNTVCTSS_EL0:
    case SpecialInstOpcode::X86_RDTSC:
    case SpecialInstOpcode::X86_RDTSCP:
      if (t->tsc_mode == PR_TSC_SIGSEGV) {
        return false;
      }
      break;
    case SpecialInstOpcode::X86_CPUID:
      if (t->cpuid_mode == 0) {
        return false;
      }
      break;
    default:
      return false;
  }

  size_t len = special_instruction_len(special_instruction.opcode);
  ASSERT(t, len > 0);

  Registers r = t->regs();
  bool should_retry_patch = false;
  if (special_instruction.opcode == SpecialInstOpcode::ARM_MRS_CNTVCT_EL0 ||
      special_instruction.opcode == SpecialInstOpcode::ARM_MRS_CNTVCTSS_EL0) {
    if (special_instruction.regno != 31) {
      r.set_x(special_instruction.regno, cntvct());
    }
  } else if (special_instruction.opcode == SpecialInstOpcode::ARM_MRS_CNTFRQ_EL0) {
    if (special_instruction.regno != 31) {
      r.set_x(special_instruction.regno, cntfrq());
    }
  } else if (special_instruction.opcode == SpecialInstOpcode::X86_RDTSC ||
             special_instruction.opcode == SpecialInstOpcode::X86_RDTSCP) {
    if (special_instruction.opcode == SpecialInstOpcode::X86_RDTSC &&
        t->vm()->monkeypatcher().try_patch_trapping_instruction(t, len, true, should_retry_patch)) {
      Event ev = Event::patch_syscall();
      ev.PatchSyscall().patch_trapping_instruction = true;
      t->record_event(ev);
      t->push_event(Event::noop());
      return true;
    }

    unsigned long long current_time = rdtsc();
    r.set_rdtsc_output(current_time);

    LOG(debug) << " trapped for rdtsc: returning " << current_time;
  } else if (special_instruction.opcode == SpecialInstOpcode::X86_CPUID) {
    auto eax = r.syscallno();
    auto ecx = r.cx();
    auto cpuid_data = cpuid(eax, ecx);
    t->session().disable_cpuid_features()
        .amend_cpuid_data(eax, ecx, &cpuid_data);
    r.set_cpuid_output(cpuid_data.eax, cpuid_data.ebx, cpuid_data.ecx,
                       cpuid_data.edx);
    LOG(debug) << " trapped for cpuid: " << HEX(eax) << ":" << HEX(ecx);
  }

  r.set_ip(r.ip() + len);
  t->set_regs(r);
  t->record_event(Event::instruction_trap());

  if (should_retry_patch) {
    LOG(debug) << "Retrying deferred syscall patching";
    should_retry_patch = false;
    if (t->vm()->monkeypatcher().try_patch_trapping_instruction(t, len, false, should_retry_patch)) {
      // Instruction was patched. Emit event.
      auto ev = Event::patch_syscall();
      ev.PatchSyscall().patch_after_syscall = true;
      t->record_event(ev);
    }
    ASSERT(t, !should_retry_patch);
  }

  t->push_event(Event::noop());
  return true;
}

/**
 * Return true if |t| was stopped because of a SIGSEGV and we want to retry
 * the instruction after emulating MAP_GROWSDOWN.
 */
static bool try_grow_map(RecordTask* t, siginfo_t* si) {
  ASSERT(t, si->si_signo == SIGSEGV);

  // Use kernel_abi to avoid odd inconsistencies between distros
  auto arch_si = reinterpret_cast<NativeArch::siginfo_t*>(si);
  auto addr = arch_si->_sifields._sigfault.si_addr_.rptr();
  if (t->try_grow_map(addr)) {
    t->push_event(Event::noop());
    return true;
  }
  return false;
}

const uint64_t MAX_PROT_INTERVAL = 16*1024;

static bool try_overlay_permission(RecordTask& t, siginfo_t* si) {
  ASSERT(&t, si->si_signo == SIGSEGV);
  if (!t.hpc.is_software_counter()) {
    return false;
  }

  // Use kernel_abi to avoid odd inconsistencies between distros
  const auto arch_si = reinterpret_cast<NativeArch::siginfo_t*>(si);
  const auto addr_page_raw =
      (arch_si->_sifields._sigfault.si_addr_.rptr().as_int() / page_size()) *
      page_size();
  if (arch_si->si_code != SEGV_ACCERR || !t.vm()->has_mapping(addr_page_raw)) {
    return false;
  }

  auto map = t.vm()->mapping_of(addr_page_raw);
  bool oexec = t.vm()->mapping_flags_of(addr_page_raw) &
               AddressSpace::Mapping::IS_SOFTWARE_COUNTER_OVERLAY_EXEC;
  if (oexec) {
    auto maybe_unique_id = t.vm()->mapping_unique_id_of(addr_page_raw);
    LOG(debug) << "unique id of `" << map.map.fsname() << "` is: "
               << (maybe_unique_id ? *maybe_unique_id : "`-- not found --`");
    auto prot = map.map.prot();
    if (oexec && !(prot & PROT_EXEC)) {
      uint64_t min_start = map.map.start().as_int();
      if (addr_page_raw - min_start > MAX_PROT_INTERVAL) {
        min_start = addr_page_raw - MAX_PROT_INTERVAL;
      }
      uint64_t max_end = map.map.end().as_int();
      if (max_end - addr_page_raw > MAX_PROT_INTERVAL) {
        max_end = addr_page_raw + MAX_PROT_INTERVAL;
      }
      LOG(debug) << "try_overlay_permission: mprotect `" << map.map.fsname() << "` "
                 << HEX(min_start) << "-"
                 << HEX(max_end)
                 << " with: " << prot_flags_string(prot | PROT_EXEC);
      size_t siz = max_end - min_start;
      {
        AutoRemoteSyscalls remote(&t,
                                  AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
        int mprotect_syscallno = syscall_number_for_mprotect(t.arch());
        int ret = remote.infallible_syscall_if_alive(
            mprotect_syscallno, min_start, siz, prot | PROT_EXEC);
        if (ret == -ESRCH) {
          LOG(warn) << "try_overlay_permission: Could not perform syscall "
                       "mprotect in tracee. Tracee dying ?";
          return false;
        }
      }
      t.vm()->protect(&t, min_start, siz, prot | PROT_EXEC);
      const auto& new_mapping = t.vm()->mapping_of(min_start);
      auto& new_mapping_flags = t.vm()->mapping_flags_of(min_start);
      new_mapping_flags &=
          ~AddressSpace::Mapping::IS_SOFTWARE_COUNTER_OVERLAY_EXEC;
      if (maybe_unique_id) {
        std::optional<RecordSession::cached_data> mc =
            t.session().get_db_of_patch_locations(*maybe_unique_id);
        if (mc) {
          t.vm()->monkeypatcher().instrument_with_software_counters(
              t, min_start, min_start + siz,
              new_mapping.map, mc->db);
          LOG(debug) << "Completed software counter instrumentation after "
                        "SIGSEGV for `"
                     << map.map.fsname() << "` from: " << HEX(min_start) << "-"
                     << HEX(max_end);
        }
      }

      t.session().accumulate_sc_jii_SIGSEGV();
      struct mprotect_record rec{ .start = min_start,
                                  .size = siz,
                                  .prot = prot | PROT_EXEC,
                                  .overlay_exec = 0 };
      Event ev = Event(rec);
      t.record_event(ev, RecordTask::DONT_FLUSH_SYSCALLBUF);
      t.push_event(Event::noop());
      return true;
    }
  }
  LOG(debug)
      << "try_overlay_permission: No overlay exec exists for the map named `"
      << map.map.fsname() << "` from: " << map.map.start() << "-"
      << map.map.end();
  return false;
}

void disarm_desched_event(RecordTask* t) {
  ScopedFd& fd = t->desched_fd.tracee_fd();
  if (fd.is_open() && ioctl(fd, PERF_EVENT_IOC_DISABLE, 0)) {
    FATAL() << "Failed to disarm desched event";
  }
}

void arm_desched_event(RecordTask* t) {
  ScopedFd& fd = t->desched_fd.tracee_fd();
  if (fd.is_open() && ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
    FATAL() << "Failed to arm desched event";
  }
}

bool desched_event_armed(RecordTask *t) {
  if (t->syscallbuf_child == nullptr) {
    return false;
  }
  bool ok = true;
  bool is_armed = t->read_mem(
    REMOTE_PTR_FIELD(t->syscallbuf_child, desched_signal_may_be_relevant), &ok);
  if (!ok) {
    // If we can't read this (perhaps syscallbuf isn't actually mapped), it's not armed
    return false;
  }
  return is_armed;
}

template <typename Arch>
static remote_code_ptr get_stub_scratch_1_arch(RecordTask* t) {
  auto remote_locals = AddressSpace::preload_thread_locals_start()
    .cast<preload_thread_locals<Arch>>();
  auto remote_stub_scratch_1 = REMOTE_PTR_FIELD(remote_locals, stub_scratch_1);
  return t->read_mem(remote_stub_scratch_1).rptr().as_int();
}

static remote_code_ptr get_stub_scratch_1(RecordTask* t) {
  RR_ARCH_FUNCTION(get_stub_scratch_1_arch, t->arch(), t);
}

template <typename Arch>
static void get_stub_scratch_2_arch(RecordTask* t, void *buff, size_t sz) {
  auto remote_locals = AddressSpace::preload_thread_locals_start()
    .cast<preload_thread_locals<Arch>>();
  auto remote_stub_scratch_2 = REMOTE_PTR_FIELD(remote_locals, stub_scratch_2);
  t->read_bytes_helper(remote_stub_scratch_2, sz, buff);
}

static void get_stub_scratch_2(RecordTask* t, void *buff, size_t sz) {
  RR_ARCH_FUNCTION(get_stub_scratch_2_arch, t->arch(), t, buff, sz);
}

/**
 * This function is responsible for handling breakpoints we set in syscallbuf
 * code to detect sigprocmask calls and syscallbuf exit. It's called when we
 * get a SIGTRAP. Returns true if the SIGTRAP was called by one of our
 * breakpoints and should be hidden from the application.
 * If it was triggered by one of our breakpoints, we have to call
 * restore_sighandler_if_not_default(t, SIGTRAP) to make sure the SIGTRAP
 * handler is properly restored if the kernel cleared it.
 */
bool handle_syscallbuf_breakpoint(RecordTask* t) {
  if (t->is_at_syscallbuf_final_instruction_breakpoint()) {
    LOG(debug) << "Reached final syscallbuf instruction, singlestepping to "
                  "enable signal dispatch";
    // Emulate the effect of the return from syscallbuf.
    // On x86, this is a single instruction that jumps to the location stored in
    // preload_thread_locals::stub_scratch_1.
    // On aarch64, the target of the jump is an instruction that restores
    // x15 and x30 and then jump back to the syscall.
    // To minimize the surprise to the tracee if we decide to deliver a signal
    // we'll emulate the register restore and return directly to the syscall site.
    // The address in stub_scratch_1 is already the correct address for this.
    if (t->arch() == aarch64) {
      uint64_t x15_x30[2];
      get_stub_scratch_2(t, x15_x30, 16);
      Registers r = t->regs();
      r.set_x(15, x15_x30[0]);
      r.set_x(30, x15_x30[1]);
      t->set_regs(r);
      t->count_direct_jump();
    }
    t->emulate_jump(get_stub_scratch_1(t));

    restore_sighandler_if_not_default(t, SIGTRAP);
    // Now we're back in application code so any pending stashed signals
    // will be handled.
    return true;
  }

  if (t->is_at_syscallstub_exit_breakpoint()) {
    LOG(debug) << "Reached syscallstub exit instruction, singlestepping to "
                  "enable signal dispatch";
    ASSERT(t, t->arch() == aarch64 && t->syscallstub_exit_breakpoint);
    auto retaddr_addr = t->syscallstub_exit_breakpoint.to_data_ptr<uint8_t>() + 3 * 4;
    uint64_t retaddr;
    t->read_bytes_helper(retaddr_addr, sizeof(retaddr), &retaddr);
    Registers r = t->regs();
    r.set_ip(retaddr);
    t->set_regs(r);
    t->count_direct_jump();
    t->syscallstub_exit_breakpoint = nullptr;
    restore_sighandler_if_not_default(t, SIGTRAP);
    // Now we're back in application code so any pending stashed signals
    // will be handled.
    return true;
  }

  if (!t->is_at_syscallbuf_syscall_entry_breakpoint()) {
    return false;
  }

  Registers r = t->regs();
  r.set_ip(r.ip().undo_executed_bkpt(t->arch()));
  t->set_regs(r);

  if (t->is_at_traced_syscall_entry()) {
    // We will automatically dispatch stashed signals now since this is an
    // allowed place to dispatch signals.
    LOG(debug) << "Allowing signal dispatch at traced-syscall breakpoint";
    restore_sighandler_if_not_default(t, SIGTRAP);
    return true;
  }

  // We're at an untraced-syscall entry point.
  // To allow an AutoRemoteSyscall, we need to make sure desched signals are
  // disarmed (and rearmed afterward).
  bool armed_desched_event = desched_event_armed(t);
  if (armed_desched_event) {
    disarm_desched_event(t);
  }
  restore_sighandler_if_not_default(t, SIGTRAP);
  if (armed_desched_event) {
    arm_desched_event(t);
  }

  // This is definitely a native-arch syscall.
  if (is_rt_sigprocmask_syscall(r.syscallno(), t->arch())) {
    // Don't proceed with this syscall. Emulate it returning EAGAIN.
    // Syscallbuf logic will retry using a traced syscall instead.
    r.set_syscall_result(-EAGAIN);
    r.set_ip(r.ip().increment_by_syscall_insn_length(t->arch()));
    t->set_regs(r);
    t->canonicalize_regs(t->arch());
    LOG(debug) << "Emulated EAGAIN to avoid untraced sigprocmask with pending "
                  "stashed signal";
    // Leave breakpoints enabled since we want to break at the traced-syscall
    // fallback for rt_sigprocmask.
    return true;
  }

  // We can proceed with the untraced syscall. Either it will complete and
  // execution will continue until we reach some point where we can deliver our
  // signal, or it will block at which point we'll be able to deliver our
  // signal.
  LOG(debug) << "Disabling breakpoints at untraced syscalls";
  t->break_at_syscallbuf_untraced_syscalls = false;
  return true;
}

/**
 * Return the event needing to be processed after this desched of |t|.
 * The tracee's execution may be advanced, and if so |regs| is updated
 * to the tracee's latest state.
 */
static void handle_desched_event(RecordTask* t) {
  /* If the tracee isn't in the critical section where a desched
   * event is relevant, we can ignore it.  See the long comments
   * in syscall_buffer.c.
   *
   * It's OK if the tracee is in the critical section for a
   * may-block syscall B, but this signal was delivered by an
   * event programmed by a previous may-block syscall A.
   *
   * If we're running in a signal handler inside an interrupted syscallbuf
   * system call, never do anything here. Syscall buffering is disabled and
   * the desched_signal_may_be_relevant was set by the outermost syscallbuf
   * invocation.
   */
  if (!desched_event_armed(t) || t->running_inside_desched()) {
    LOG(debug) << "  (not entering may-block syscall; resuming)";
    /* We have to disarm the event just in case the tracee
     * has cleared the relevancy flag, but not yet
     * disarmed the event itself. */
    disarm_desched_event(t);
    t->push_event(Event::noop());
    return;
  }

  /* TODO: how can signals interrupt us here? */

  /* The desched event just fired.  That implies that the
   * arm-desched ioctl went into effect, and that the
   * disarm-desched syscall didn't take effect.  Since a signal
   * is pending for the tracee, then if the tracee was in a
   * syscall, linux has exited it with an -ERESTART* error code.
   * That means the tracee is about to (re-)enter either
   *
   *  1. buffered syscall
   *  2. disarm-desched ioctl syscall
   *
   * We can figure out which one by simply issuing a
   * ptrace(SYSCALL) and examining the tracee's registers.
   *
   * If the tracee enters the disarm-desched ioctl, it's going
   * to commit a record of the buffered syscall to the
   * syscallbuf, and we can safely send the tracee back on its
   * way, ignoring the desched completely.
   *
   * If it enters the buffered syscall, then the desched event
   * has served its purpose and we need to prepare the tracee to
   * be context-switched.
   *
   * An annoyance of the desched signal is that when the tracer
   * is descheduled in interval (C) above, we see normally (see
   * below) see *two* signals.  The current theory of what's
   * happening is
   *
   *  o child gets descheduled, bumps counter to i and schedules
   *    signal
   *  o signal notification "schedules" child, but it doesn't
   *    actually run any application code
   *  o child is being ptraced, so we "deschedule" child to
   *    notify parent and bump counter to i+1.  (The parent
   *    hasn't had a chance to clear the counter yet.)
   *  o another counter signal is generated, but signal is
   *    already pending so this one is queued
   *  o parent is notified and sees counter value i+1
   *  o parent stops delivery of first signal and disarms
   *    counter
   *  o second signal dequeued and delivered, notifying parent
   *    (counter is disarmed now, so no pseudo-desched possible
   *    here)
   *  o parent notifiedand sees counter value i+1 again
   *  o parent stops delivery of second signal and we continue on
   *
   * So we "work around" this by the tracer expecting two signal
   * notifications, and silently discarding both.
   *
   * One really fun edge case is that sometimes the desched
   * signal will interrupt the arm-desched syscall itself.
   * Continuing to the next syscall boundary seems to restart
   * the arm-desched syscall, and advancing to the boundary
   * again exits it and we start receiving desched signals
   * again.
   *
   * That may be a kernel bug, but we handle it by just
   * continuing until we we continue past the arm-desched
   * syscall *and* stop seeing signals. */

  const auto untraced_record_only_entry =
    uintptr_t(RR_PAGE_SYSCALL_UNTRACED_RECORDING_ONLY);
  auto syscall_entry_ip = t->ip().decrement_by_syscall_insn_length(t->arch());
  if (syscall_entry_ip == remote_code_ptr(untraced_record_only_entry) &&
      t->regs().syscall_result_signed() == -EFAULT) {
    intptr_t syscallno;
    if (t->arch() == aarch64) {
      // Untraced syscall, we may not have set original_syscallno for this on aarch64.
      syscallno = t->regs().syscallno();
    } else {
      // On x86, syscall no is overwritten by return value.
      ASSERT(t, is_x86ish(t->arch()));
      syscallno = t->regs().original_syscallno();
    }
    if (syscallno == syscall_number_for_getsockopt(t->arch())) {
      // We've observed interrupted getsockopt syscalls returning `EFAULT`
      // rather than the normal ERESTART*.
      // This is a kernel bug caused by CONFIG_BPFILTER_UMH.
      // Try to reduce the effect caused by rr generated signals
      // by manually restarting the syscall
      // (since the previous syscall returned EFAULT
      //  we would in the worst case just get another EFAULT).
      // Note that setting syscall result to ERESTART* wouldn't work on aarch64
      // if the arg1 has been overwritten by AutoRemoteSyscalls.
      auto r = t->regs();
      r.set_ip(syscall_entry_ip);
      if (t->arch() == aarch64) {
        // On AArch64, we need to restore arg1 from the stack argument from syscallbuf.
        auto orig_arg1_ptr = r.sp() + sizeof(long);
        auto orig_arg1 = t->read_mem(orig_arg1_ptr.cast<long>());
        r.set_arg1(orig_arg1);
      } else {
        ASSERT(t, is_x86ish(t->arch()));
        // On x86, we need to restore syscall number
        r.set_syscallno(syscallno);
      }
      t->set_regs(r);
    }
  }

  while (true) {
    // Prevent further desched notifications from firing
    // while we're advancing the tracee.  We're going to
    // leave it in a consistent state anyway, so the event
    // is no longer useful.  We have to do this in each
    // loop iteration because a restarted arm-desched
    // syscall may have re-armed the event.
    disarm_desched_event(t);

    if (!t->resume_execution(RESUME_SYSCALL, RESUME_WAIT_NO_EXIT, RESUME_UNLIMITED_TICKS)) {
      LOG(debug) << "  (got exit, bailing out)";
      t->push_event(Event::noop());
      return;
    }

    if (t->status().is_syscall()) {
      t->apply_syscall_entry_regs();
      if (t->is_arm_desched_event_syscall()) {
        continue;
      }
      break;
    }
    if (t->ptrace_event() == PTRACE_EVENT_SECCOMP) {
      ASSERT(t,
             t->session().syscall_seccomp_ordering() ==
                 Session::SECCOMP_BEFORE_PTRACE_SYSCALL);
      // This is the old kernel event ordering. This must be a SECCOMP event
      // for the buffered syscall; it's not rr-generated because this is an
      // untraced syscall, but it could be generated by a tracee's
      // seccomp filter.
      break;
    }

    // Completely ignore spurious desched signals and
    // signals that aren't going to be delivered to the
    // tracee.
    //
    // Also ignore time-slice signals.  If the tracee ends
    // up at the disarm-desched ioctl, we'll reschedule it
    // with the ticks interrupt still programmed.  At worst,
    // the tracee will get an extra time-slice out of
    // this, on average, so we don't worry too much about
    // it.
    //
    // TODO: it's theoretically possible for this to
    // happen an unbounded number of consecutive times
    // and the tracee never switched out.
    int sig = t->stop_sig();
    ASSERT(t, sig) << "expected stop-signal, got " << t->status();
    if (SIGTRAP == sig && handle_syscallbuf_breakpoint(t)) {
      // We stopped at a breakpoint on an untraced may-block syscall.
      // This can't be relevant to us since sigprocmask isn't may-block.
      LOG(debug) << " disabling breakpoints on untraced syscalls";
      continue;
    }
    if (t->session().syscallbuf_desched_sig() == sig ||
        PerfCounters::TIME_SLICE_SIGNAL == sig || t->is_sig_ignored(sig)) {
      LOG(debug) << "  dropping ignored " << signal_name(sig);
      continue;
    }

    LOG(debug) << "  stashing " << signal_name(sig);
    t->stash_sig();
  }

  if (t->is_disarm_desched_event_syscall()) {
    LOG(debug)
        << "  (at disarm-desched, so finished buffered syscall; resuming)";
    t->push_event(Event::noop());
    return;
  }

  if (t->desched_rec()) {
    // We're already processing a desched. We probably reexecuted the
    // system call (e.g. because a signal was processed) and the syscall
    // blocked again. Carry on with the current desched.
  } else {
    /* This prevents the syscallbuf record counter from being
     * reset until we've finished guiding the tracee through this
     * interrupted call.  We use the record counter for
     * assertions. */
    ASSERT(t, !t->delay_syscallbuf_reset_for_desched);
    t->delay_syscallbuf_reset_for_desched = true;
    LOG(debug) << "Desched initiated";

    /* The tracee is (re-)entering the buffered syscall.  Stash
     * away this breadcrumb so that we can figure out what syscall
     * the tracee was in, and how much "scratch" space it carved
     * off the syscallbuf, if needed. */
    remote_ptr<const struct syscallbuf_record> desched_rec =
        t->next_syscallbuf_record();
    t->push_event(DeschedEvent(desched_rec));
    int call = t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(), syscallno));

    /* The descheduled syscall was interrupted by a signal, like
     * all other may-restart syscalls, with the exception that
     * this one has already been restarted (which we'll detect
     * back in the main loop). */
    t->push_event(Event(interrupted, SyscallEvent(call, t->arch())));
    SyscallEvent& ev = t->ev().Syscall();
    ev.desched_rec = desched_rec;
  }

  SyscallEvent& ev = t->ev().Syscall();
  ev.regs = t->regs();
  /* For some syscalls (at least poll) but not all (at least not read),
   * repeated cont_syscall()s above of the same interrupted syscall
   * can set $orig_eax to 0 ... for unclear reasons. Fix that up here
   * otherwise we'll get a divergence during replay, which will not
   * encounter this problem.
   */
  int call = t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(), syscallno));
  ev.regs.set_original_syscallno(call);
  t->set_regs(ev.regs);
  // runnable_state_changed will observe us entering this syscall and change
  // state to ENTERING_SYSCALL

  LOG(debug) << "  resuming (and probably switching out) blocked `"
             << syscall_name(call, ev.arch()) << "'";
}

static bool is_safe_to_deliver_signal(RecordTask* t, siginfo_t* si) {
  if (!t->is_in_syscallbuf()) {
    /* The tracee is outside the syscallbuf code,
     * so in most cases can't possibly affect
     * syscallbuf critical sections.  The
     * exception is signal handlers "re-entering"
     * desched'd syscalls, which are OK. */
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because not in syscallbuf";
    return true;
  }

  // Note that this will never fire on aarch64 in a signal stop
  // since the ip has been moved to the syscall entry.
  // We will catch it in the traced_syscall_entry case below.
  // We will miss the exit for rrcall_notify_syscall_hook_exit
  // but that should not be a big problem.
  if (t->is_in_traced_syscall()) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because in traced syscall";
    return true;
  }

  // Don't deliver signals just before entering rrcall_notify_syscall_hook_exit.
  // At that point, notify_on_syscall_hook_exit will be set, but we have
  // passed the point at which syscallbuf code has checked that flag.
  // Replay will set notify_on_syscall_hook_exit when we replay towards the
  // rrcall_notify_syscall_hook_exit *after* handling this signal, but
  // that will be too late for syscallbuf to notice.
  // It's OK to delay signal delivery until after rrcall_notify_syscall_hook_exit
  // anyway.
  if (t->is_at_traced_syscall_entry() &&
      !is_rrcall_notify_syscall_hook_exit_syscall(t->regs().syscallno(), t->arch())) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because at entry to traced syscall";
    return true;
  }

  // On aarch64, the untraced syscall here include both entry and exit
  // if we are at a signal stop.
  if (t->is_in_untraced_syscall() && t->desched_rec()) {
    // Untraced syscalls always use the architecture of the process
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because tracee interrupted by desched of "
               << syscall_name(t->read_mem(REMOTE_PTR_FIELD(t->desched_rec(),
                                                            syscallno)),
                               t->arch());
    return true;
  }

  if (t->is_in_untraced_syscall() && si->si_signo == SIGSYS &&
      si->si_code == SYS_SECCOMP) {
    LOG(debug) << "Safe to deliver signal at " << t->ip()
               << " because signal is seccomp trap.";
    return true;
  }

  // If the syscallbuf buffer hasn't been created yet, just delay the signal
  // with no need to set notify_on_syscall_hook_exit; the signal will be
  // delivered when rrcall_init_buffers is called.
  if (t->syscallbuf_child) {
    if (t->read_mem(REMOTE_PTR_FIELD(t->syscallbuf_child, locked)) & 2) {
      LOG(debug) << "Safe to deliver signal at " << t->ip()
                 << " because the syscallbuf is locked";
      return true;
    }

    // A signal (e.g. seccomp SIGSYS) interrupted a untraced syscall in a
    // non-restartable way. Defer it until SYS_rrcall_notify_syscall_hook_exit.
    if (t->is_in_untraced_syscall()) {
      // Our emulation of SYS_rrcall_notify_syscall_hook_exit clears this flag.
      t->write_mem(
          REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit),
          (uint8_t)1);
    }
  }

  LOG(debug) << "Not safe to deliver signal at " << t->ip();
  return false;
}

SignalHandled handle_signal(RecordTask* t, siginfo_t* si,
                            SignalDeterministic deterministic,
                            SignalBlocked signal_was_blocked) {
  int sig = si->si_signo;
  LOG(debug) << t->tid << ": handling signal " << signal_name(sig)
             << " (pevent: " << ptrace_event_name(t->ptrace_event())
             << ", event: " << t->ev();

  // Conservatively invalidate the sigmask in case just accepting a signal has
  // sigmask effects.
  t->invalidate_sigmask();

  if (deterministic == DETERMINISTIC_SIG) {
    // When a deterministic signal is triggered, but the signal is currently
    // blocked or ignored, the kernel (in |force_sig_info|) unblocks it and
    // sets its disposition to SIG_DFL. It never undoes this (probably
    // because it expects the signal to be fatal, which it always would be
    // unless a ptracer intercepts the signal as we do). Therefore, if the
    // signal was generated for rr's purposes, we need to restore the signal
    // state ourselves.
    if (sig == SIGSEGV &&
        (try_handle_trapped_instruction(t, si) || try_grow_map(t, si) ||
         try_overlay_permission(*t, si))) {
      if (signal_was_blocked || t->is_sig_ignored(sig)) {
        restore_signal_state(t, sig, signal_was_blocked);
      }
      return SIGNAL_HANDLED;
    }

    // Since we're not undoing the kernel's changes, update our signal handler
    // state to match the kernel's.
    if (signal_was_blocked || t->is_sig_ignored(sig)) {
      t->did_set_sig_handler_default(sig);
    }
  }

  if (!VirtualPerfCounterMonitor::is_virtual_perf_counter_signal(si)) {
    /* We have to check for a desched event first, because for
     * those we *do not* want to (and cannot, most of the time)
     * step the tracee out of the syscallbuf code before
     * attempting to deliver the signal. */
    if (t->session().syscallbuf_desched_sig() == si->si_signo &&
        si->si_code == POLL_IN) {
      handle_desched_event(t);
      return SIGNAL_HANDLED;
    }

    if (!is_safe_to_deliver_signal(t, si)) {
      return DEFER_SIGNAL;
    }

    t->set_siginfo_for_synthetic_SIGCHLD(si);

    if (sig == PerfCounters::TIME_SLICE_SIGNAL) {
      t->push_event(Event::sched());
      return SIGNAL_HANDLED;
    }
  } else {
    // Clear the magic flag so it doesn't leak into the program.
    si->si_errno = 0;
  }

  /* This signal was generated by the program or an external
   * source, record it normally. */

  if (t->emulate_ptrace_stop(WaitStatus::for_stop_sig(sig), si)) {
    // Record an event so that replay progresses the tracee to the
    // current point before we notify the tracer.
    // If the signal is deterministic, record it as an EV_SIGNAL so that
    // we replay it using the deterministic-signal replay path. This is
    // more efficient than emulate_async_signal. Also emulate_async_signal
    // currently assumes it won't encounter a deterministic SIGTRAP (due to
    // a hardcoded breakpoint in the tracee).
    if (deterministic == DETERMINISTIC_SIG) {
      t->record_event(Event(EV_SIGNAL, SignalEvent(*si, deterministic,
                                                   t->sig_resolved_disposition(
                                                       sig, deterministic))));
    } else {
      t->record_event(Event::sched());
    }
    // ptracer has been notified, so don't deliver the signal now.
    // The signal won't be delivered for real until the ptracer calls
    // PTRACE_CONT with the signal number (which we don't support yet!).
    return SIGNAL_PTRACE_STOP;
  }

  t->push_event(Event(
      EV_SIGNAL, SignalEvent(*si, deterministic,
                             t->sig_resolved_disposition(sig, deterministic))));
  return SIGNAL_HANDLED;
}

} // namespace rr
