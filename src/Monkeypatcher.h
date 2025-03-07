/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_MONKEYPATCHER_H_
#define RR_MONKEYPATCHER_H_

#include <map>
#include <unordered_set>
#include <vector>

#include <rocksdb/db.h>
#include <rocksdb/comparator.h>

#include "ElfReader.h"
#include "preload/preload_interface.h"

#include "remote_code_ptr.h"
#include "remote_ptr.h"
#include "util.h"

namespace rr {

const size_t SC_MMAP_AREA = 0x20000;
// Needs to be an exact multiple of 0x1000 (smallest page size on aarch64/x86)
static_assert(SC_MMAP_AREA % 0x1000 == 0);

class ElfReader;
class RecordTask;
class ScopedFd;
class Task;

enum PatchCategory: uint8_t {
  WIDE_COND_BRANCH
};
struct __attribute__((packed)) PatchData {
  uint64_t elf_addr = 0;
  PatchCategory category = WIDE_COND_BRANCH;
  uint8_t len = 0;
  // delta from the instruction start rather than next instruction start
  int64_t actual_delta = 0;
  uint8_t data[];
};

/**
 * A class encapsulating patching state. There is one instance of this
 * class per tracee address space. Currently this class performs the following
 * tasks:
 *
 * 1) Patch the VDSO's user-space-only implementation of certain system calls
 * (e.g. gettimeofday) to do a proper kernel system call instead, so rr can
 * trap and record it (x86-64 only).
 *
 * 2) Patch the VDSO __kernel_vsyscall fast-system-call stub to redirect to
 * our syscall hook in the preload library (x86 only).
 *
 * 3) Patch syscall instructions whose following instructions match a known
 * pattern to call the syscall hook.
 *
 * Monkeypatcher only runs during recording, never replay.
 */
class Monkeypatcher {
public:
  Monkeypatcher() {}
  Monkeypatcher(const Monkeypatcher&) = default;

  /**
   * Apply any necessary patching immediately after exec.
   * In this hook we patch everything that doesn't depend on the preload
   * library being loaded.
   */
  void patch_after_exec(RecordTask* t);

  /**
   * During librrpreload initialization, apply patches that require the
   * preload library to be initialized.
   */
  void patch_at_preload_init(RecordTask* t);

  /**
   * Try to patch the syscall instruction that |t| just entered. If this
   * returns false, patching failed and the syscall should be processed
   * as normal. If this returns true, patching succeeded and the syscall
   * was aborted; ip() has been reset to the start of the patched syscall,
   * and execution should resume normally to execute the patched code.
   * Zero or more mapping operations are also recorded to the trace and must
   * be replayed.
   */
  bool try_patch_syscall(RecordTask* t, bool entering_syscall, bool &should_retry);
  bool try_patch_syscall(RecordTask* t, bool entering_syscall, bool &should_retry, remote_code_ptr ip);

  bool try_patch_syscall_x86ish(RecordTask* t, remote_code_ptr ip, bool entering_syscall,
                                SupportedArch arch, bool &should_retry);
  bool try_patch_syscall_aarch64(RecordTask* t, remote_code_ptr ip, bool entering_syscall);

  /**
   * Try to patch the trapping instruction that |t| just trapped on. If this
   * returns false, patching failed and the instruction should be processed
   * as normal. If this returns true, patching succeeded.
   * t->ip() is the address of the trapping instruction.
   * and execution should resume normally to execute the patched code.
   * Zero or more mapping operations are also recorded to the trace and must
   * be replayed.
   */
  bool try_patch_trapping_instruction(RecordTask* t, size_t instruction_length,
                                      bool before_instruction,
                                      bool &should_retry);

  /**
   * Replace all extended jumps by syscalls again. Note that we do not try to
   * patch the original locations, since we don't know what the tracee may have
   * done with them in the meantime, we only patch the extended jump stubs,
   * which the tracee isn't allowed to touch.
   */
  void unpatch_syscalls_in(Task *t);

  /**
   * Try to patch the vsyscall-entry pattern occurring right before ret_addr
   * to instead point into the corresponding entry points in the vdso.
   * Returns true if the patching succeeded, false if it doesn't. The tasks
   * registers are left unmodified.
   */
  bool try_patch_vsyscall_caller(RecordTask *t, remote_code_ptr ret_addr);

  void init_dynamic_syscall_patching(
      RecordTask* t, int syscall_patch_hook_count,
      remote_ptr<syscall_patch_hook> syscall_patch_hooks);

  /**
   * Try to allocate a stub from the sycall patching stub buffer. Returns null
   * if there's no buffer or we've run out of free stubs.
   */
  remote_ptr<uint8_t> allocate_stub(RecordTask* t, size_t bytes);

  enum MmapMode {
    MMAP_EXEC,
    MMAP_SYSCALL,
  };
  /**
   * Apply any necessary patching immediately after an mmap. We use this to
   * patch libpthread.so.
   */
  void patch_after_mmap(RecordTask* t, remote_ptr<void> start, size_t size,
                        size_t offset_bytes, int child_fd, MmapMode mode);

  struct ExtendedJumpPage {
    ExtendedJumpPage(remote_ptr<uint8_t> addr) : addr(addr), allocated(0) {}
    remote_ptr<uint8_t> addr;
    size_t allocated;
  };
  /**
   * The list of pages we've allocated to hold our extended jumps.
   */
  std::vector<ExtendedJumpPage> extended_jump_pages;

  void instrument_with_software_counters(
      RecordTask& t, const remote_ptr<void> instrumentation_addr_start,
      const remote_ptr<void> instrumentation_addr_end, const KernelMapping& map,
      rocksdb::DB& db);

  void software_counter_instrument_after_mmap(
      RecordTask& t, const remote_ptr<void> start_region,
      const size_t size_region, const size_t offset_bytes, int child_fd,
      const MmapMode mode);

  struct JumpStubArea {
    JumpStubArea(remote_ptr<uint8_t> start_addr, size_t jump_area_size)
        : jump_area_start(start_addr), jump_area_size(jump_area_size), allocated_bytes(0) {}
    const remote_ptr<uint8_t> jump_area_start;
    const size_t jump_area_size;
    size_t allocated_bytes;
  };
  std::vector<JumpStubArea> software_counter_stub_areas;
  size_t last_used_software_counter_stub_area = 0;

  bool is_jump_stub_instruction(remote_code_ptr p, bool include_safearea);
  // Return the breakpoint instruction (i.e. the last branch back to caller)
  // if we are on the exit path in the jump stub
  remote_code_ptr get_jump_stub_exit_breakpoint(remote_code_ptr ip, RecordTask *t);

  void unpatch_dl_runtime_resolves(RecordTask* t);

  struct patched_syscall {
    // Pointer to hook inside the syscall_hooks array, which gets initialized
    // once and is fixed afterwards.
    const syscall_patch_hook *hook;
    size_t size;
    uint16_t safe_prefix = 0;
    uint16_t safe_suffix = 0;
  };

  /**
   * Addresses/lengths of syscallbuf stubs.
   */
  std::map<remote_ptr<uint8_t>, patched_syscall> syscallbuf_stubs;

private:
  void patch_dl_runtime_resolve(RecordTask* t, ElfReader& reader,
                                uintptr_t elf_addr,
                                remote_ptr<void> map_start,
                                size_t map_size,
                                size_t map_offset);
  void patch_aarch64_have_lse_atomics(RecordTask* t, ElfReader& reader,
                                      uintptr_t elf_addr,
                                      remote_ptr<void> map_start,
                                      size_t map_size,
                                      size_t map_offset);

  /**
   * `ip` is the address of the instruction that triggered the syscall or trap
   */
  const syscall_patch_hook* find_syscall_hook(RecordTask* t,
                                              remote_code_ptr ip,
                                              bool entering_syscall,
                                              size_t instruction_length,
                                              bool &should_retry,
                                              bool &transient_failure);

  /**
   * The list of supported syscall patches obtained from the preload
   * library. Each one matches a specific byte signature for the instruction(s)
   * after a syscall instruction.
   */
  std::vector<syscall_patch_hook> syscall_hooks;
  /**
   * The addresses of the instructions following syscalls or other
   * instructions that we've tried (or are currently trying) to patch.
   */
  std::unordered_set<remote_code_ptr> tried_to_patch_syscall_addresses;

  std::map<remote_ptr<uint8_t>, std::vector<uint8_t>> saved_dl_runtime_resolve_code;
};

} // namespace rr

#endif /* RR_MONKEYPATCHER_H_ */
