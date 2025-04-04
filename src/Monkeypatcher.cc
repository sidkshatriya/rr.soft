/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Monkeypatcher.h"

#include <limits.h>
#include <linux/auxvec.h>

#include <sstream>

#include <rocksdb/iterator.h>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "ElfReader.h"
#include "Flags.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "preload/preload_interface.h"
#include "remote_code_ptr.h"
#include "rr/rr.h"
#include <elf.h>
#include <sys/mman.h>

using namespace std;

namespace rr {

#include "AssemblyTemplates.generated"

static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   size_t size, const void* buf, bool* ok = nullptr) {
  t->write_bytes_helper(child_addr, size, buf, ok);
  if (!ok || *ok) {
    t->record_local(child_addr, size, buf);
  }
}

template <size_t N>
static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   const uint8_t (&buf)[N], bool* ok = nullptr) {
  write_and_record_bytes(t, child_addr, N, buf, ok);
}

template <typename T>
static void write_and_record_mem(RecordTask* t, remote_ptr<T> child_addr,
                                 const T* val, int count) {
  t->write_bytes_helper(child_addr, sizeof(*val) * count,
                        static_cast<const void*>(val));
  t->record_local(child_addr, sizeof(T) * count, val);
}

/**
 * RecordSession sets up an LD_PRELOAD environment variable with an entry
 * SYSCALLBUF_LIB_FILENAME_PADDED (and, if enabled, an LD_AUDIT environment
 * variable with an entry RTLDAUDIT_LIB_FILENAME_PADDED) which is big enough to
 * hold either the 32-bit or 64-bit preload/audit library file names.
 * Immediately after exec we enter this function, which patches the environment
 * variable value with the correct library name for the task's architecture.
 *
 * It's possible for this to fail if a tracee alters the LD_PRELOAD value
 * and then does an exec. That's just too bad. If we ever have to handle that,
 * we should modify the environment passed to the exec call. This function
 * failing isn't necessarily fatal; a tracee might not rely on the functions
 * overridden by the preload library, or might override them itself (e.g.
 * because we're recording an rr replay).
 */
#define setup_library_path(arch, env_var, soname, task) \
  setup_library_path_arch<arch>(task, env_var, soname ## _BASE, \
                                soname ## _PADDED, soname ## _32)

template <typename Arch>
static void setup_library_path_arch(RecordTask* t, const char* env_var,
                                    const char* soname_base,
                                    const char* soname_padded,
                                    const char* soname_32) {
  const char* lib_name =
      sizeof(typename Arch::unsigned_word) < sizeof(uintptr_t)
          ? soname_32
          : soname_padded;
  auto env_assignment = string(env_var) + "=";

  auto p = t->regs().sp().cast<typename Arch::unsigned_word>();
  auto argc = t->read_mem(p);
  p += 1 + argc + 1; // skip argc, argc parameters, and trailing NULL
  while (true) {
    auto envp = t->read_mem(p);
    if (!envp) {
      LOG(debug) << env_var << " not found";
      return;
    }
    string env = t->read_c_str(envp);
    if (env.find(env_assignment) != 0) {
      ++p;
      continue;
    }
    size_t lib_pos = env.find(soname_base);
    if (lib_pos == string::npos) {
      LOG(debug) << soname_base << " not found in " << env_var;
      return;
    }
    size_t next_colon = env.find(':', lib_pos);
    if (next_colon != string::npos) {
      while ((next_colon + 1 < env.length()) &&
             (env[next_colon + 1] == ':' || env[next_colon + 1] == 0)) {
        ++next_colon;
      }
      if (next_colon + 1 <
          lib_pos + sizeof(soname_padded) - 1) {
        LOG(debug) << "Insufficient space for " << lib_name
                   << " in " << env_var << " before next ':'";
        return;
      }
    }
    if (env.length() < lib_pos + sizeof(soname_padded) - 1) {
      LOG(debug) << "Insufficient space for " << lib_name
                 << " in " << env_var << " before end of string";
      return;
    }
    remote_ptr<void> dest = envp + lib_pos;
    write_and_record_mem(t, dest.cast<char>(), lib_name, strlen(soname_padded));
    return;
  }
}

template <typename Arch> static void setup_preload_library_path(RecordTask* t) {
  static_assert(sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) ==
                    sizeof(SYSCALLBUF_LIB_FILENAME_32),
                "filename length mismatch");
  setup_library_path(Arch, "LD_PRELOAD", SYSCALLBUF_LIB_FILENAME, t);
}

template <typename Arch> static void setup_audit_library_path(RecordTask* t) {
  static_assert(sizeof(RTLDAUDIT_LIB_FILENAME_PADDED) ==
                    sizeof(RTLDAUDIT_LIB_FILENAME_32),
                "filename length mismatch");
  if (t->session().use_audit()) {
    setup_library_path(Arch, "LD_AUDIT", RTLDAUDIT_LIB_FILENAME, t);
  }
}

void Monkeypatcher::init_dynamic_syscall_patching(
    RecordTask* t, int syscall_patch_hook_count,
    remote_ptr<struct syscall_patch_hook> syscall_patch_hooks) {
  if (syscall_patch_hook_count && syscall_hooks.empty()) {
    syscall_hooks = t->read_mem(syscall_patch_hooks, syscall_patch_hook_count);
  }
}

template <typename Arch>
static bool patch_syscall_with_hook_arch(Monkeypatcher& patcher, RecordTask* t,
                                         const syscall_patch_hook& hook,
                                         remote_code_ptr ip_of_instruction,
                                         size_t instruction_length,
                                         uint32_t fake_syscall_number);

template <typename StubPatch>
static void substitute(uint8_t* buffer, uint64_t return_addr,
                       uint32_t trampoline_relative_addr);

template <typename ExtendedJumpPatch>
static void substitute_extended_jump(uint8_t* buffer, uint64_t patch_addr,
                                     uint64_t return_addr,
                                     uint64_t target_addr,
                                     uint32_t fake_syscall_number);

template <>
void substitute_extended_jump<X86SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t patch_addr, uint64_t return_addr,
    uint64_t target_addr, uint32_t) {
  int64_t offset =
      target_addr -
      (patch_addr + X86SyscallStubExtendedJump::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)offset);
}

template <>
void substitute_extended_jump<X64SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t, uint64_t return_addr, uint64_t target_addr,
    uint32_t) {
  X64SyscallStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)(return_addr >> 32),
                                         target_addr);
}

template <>
void substitute_extended_jump<X86TrapInstructionStubExtendedJump>(
    uint8_t* buffer, uint64_t patch_addr, uint64_t return_addr,
    uint64_t target_addr, uint32_t fake_syscall_number) {
  int64_t offset =
      target_addr -
      (patch_addr + X86SyscallStubExtendedJump::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86TrapInstructionStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         fake_syscall_number, (uint32_t)offset);
}

template <>
void substitute_extended_jump<X64TrapInstructionStubExtendedJump>(
    uint8_t* buffer, uint64_t, uint64_t return_addr, uint64_t target_addr,
    uint32_t fake_syscall_number) {
  X64TrapInstructionStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)(return_addr >> 32),
                                         fake_syscall_number,
                                         target_addr);
}

/**
 * Allocate an extended jump in an extended jump page and return its address.
 * The resulting address must be within 2G of from_end, and the instruction
 * there must jump to to_start.
 */
template <typename ExtendedJumpPatch>
static remote_ptr<uint8_t> allocate_extended_jump_x86ish(
    RecordTask* t, vector<Monkeypatcher::ExtendedJumpPage>& pages,
    remote_ptr<uint8_t> from_end) {
  Monkeypatcher::ExtendedJumpPage* page = nullptr;
  for (auto& p : pages) {
    remote_ptr<uint8_t> page_jump_start = p.addr + p.allocated;
    int64_t offset = page_jump_start - from_end;
    if ((int32_t)offset == offset &&
        p.allocated + ExtendedJumpPatch::size <= page_size()) {
      page = &p;
      break;
    }
  }

  if (!page) {
    // We're looking for a gap of three pages --- one page to allocate and
    // a page on each side as a guard page.
    uint32_t required_space = 3 * page_size();
    remote_ptr<void> free_mem =
        t->vm()->find_free_memory(t, required_space,
                                  // Find free space after the patch site.
                                  t->vm()->mapping_of(from_end).map.start());
    if (!free_mem) {
      LOG(debug) << "Can't find free memory anywhere after the jump";
      return nullptr;
    }

    remote_ptr<uint8_t> addr = (free_mem + page_size()).cast<uint8_t>();
    int64_t offset = addr - from_end;
    if ((int32_t)offset != offset) {
      LOG(debug) << "Can't find space close enough for the jump";
      return nullptr;
    }

    {
      AutoRemoteSyscalls remote(t);
      int prot = PROT_READ | PROT_EXEC;
      int flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
      auto ret = remote.infallible_mmap_syscall_if_alive(addr, page_size(), prot, flags, -1, 0);
      if (!ret) {
        /* Tracee died */
        return nullptr;
      }
      KernelMapping recorded(addr, addr + page_size(), string(),
                             KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                             prot, flags);
      t->vm()->map(t, addr, page_size(), prot, flags, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                   &recorded);
      t->vm()->mapping_flags_of(addr) |= AddressSpace::Mapping::IS_PATCH_STUBS;
      t->trace_writer().write_mapped_region(t, recorded, recorded.fake_stat(),
                                            recorded.fsname(),
                                            vector<TraceRemoteFd>(),
                                            TraceWriter::PATCH_MAPPING);
    }

    pages.push_back(Monkeypatcher::ExtendedJumpPage(addr));
    page = &pages.back();
  }

  remote_ptr<uint8_t> jump_addr = page->addr + page->allocated;
  page->allocated += ExtendedJumpPatch::size;
  return jump_addr;
}

/**
 * Encode the standard movz|movk sequence for moving constant `v` into register `reg`
 */
static void encode_immediate_aarch64(std::vector<uint32_t> &buff,
                                     uint8_t reg, uint64_t v)
{
  DEBUG_ASSERT(reg < 31);
  const uint32_t movz_inst = 0xd2800000;
  const uint32_t movk_inst = 0xf2800000;
  uint32_t mov_inst = movz_inst;
  for (int lsl = 3; lsl >= 0; lsl--) {
    uint32_t bits = (v >> (lsl * 16)) & 0xffff;
    if (bits == 0 && !(lsl == 0 && mov_inst == movz_inst)) {
      // Skip zero bits unless it's the only instruction, i.e. v == 0
      continue;
    }
    // movz|movk x[reg], #bits, LSL #lsl
    buff.push_back(mov_inst | (uint32_t(lsl) << 21) | (bits << 5) | reg);
    mov_inst = movk_inst;
  }
}

/**
 * Encode the following assembly.
 *
 *    cmp     x8, 1024
 *    b.hi    .Lnosys
 *    movk    x8, preload_thread_locals >> 16, lsl 16
 *    stp     x15, x30, [x8, stub_scratch_2 - preload_thread_locals]
 *    movz    x30, #:abs_g3:_syscall_hook_trampoline
 *    movk    x30, #:abs_g2_nc:_syscall_hook_trampoline
 *    movk    x30, #:abs_g1_nc:_syscall_hook_trampoline
 *    movk    x30, #:abs_g0_nc:_syscall_hook_trampoline // Might be shorter depending on the address
 *    blr     x30
 *    ldp     x15, x30, [x15]
.Lreturn:
 *    b       syscall_return_address
.Lnosys:
 *    svc     0x0 // the test relies on invalid syscall triggering an event.
 *    // mov     x0, -ENOSYS
 *    b       .Lreturn
 *    .long <syscall return address>
 *
 * And return the instruction index of `.Lreturn`.
 * The branch instruction following that label will not be encoded
 * since it depends on the address of this code.
 */
static uint32_t encode_extended_jump_aarch64(std::vector<uint32_t> &buff,
                                             uint64_t target, uint64_t return_addr,
                                             uint32_t *_retaddr_idx = nullptr)
{
  // cmp x8, 1024
  buff.push_back(0xf110011f);
  uint32_t b_hi_idx = buff.size();
  buff.push_back(0); // place holder
  // movk x8, preload_thread_locals >> 16, lsl 16
  buff.push_back(0xf2ae0028);
  // stp x15, x30, [x8, #104]
  buff.push_back(0xa906f90f);
  encode_immediate_aarch64(buff, 30, target);
  // blr x30
  buff.push_back(0xd63f03c0);
  // ldp x15, x30, [x15]
  buff.push_back(0xa94079ef);
  uint32_t ret_idx = buff.size();
  buff.push_back(0); // place holder
  // b.hi . + (ret_inst + 4 - .)
  buff[b_hi_idx] = 0x54000000 | ((ret_idx + 1 - b_hi_idx) << 5) | 0x8;
  // movn x0, (ENOSYS - 1), i.e. mov x0, -ENOSYS
  // buff.push_back(0x92800000 | ((ENOSYS - 1) << 5) | 0);
  buff.push_back(0xd4000001); // svc 0
  // b .-2
  buff.push_back(0x17fffffe);
  uint32_t retaddr_idx = buff.size();
  if (_retaddr_idx)
    *_retaddr_idx = retaddr_idx;
  buff.resize(retaddr_idx + 2);
  memcpy(&buff[retaddr_idx], &return_addr, 8);
  return ret_idx;
}

// b and bl has a 26bit signed immediate in unit of 4 bytes
constexpr int32_t aarch64_b_max_offset = ((1 << 25) - 1) * 4;
constexpr int32_t aarch64_b_min_offset = (1 << 25) * -4;

static remote_ptr<uint8_t> allocate_extended_jump_aarch64(
    RecordTask* t, vector<Monkeypatcher::ExtendedJumpPage>& pages,
    remote_ptr<uint8_t> svc_ip, uint64_t to, std::vector<uint32_t> &inst_buff) {
  uint64_t return_addr = svc_ip.as_int() + 4;
  auto ret_idx = encode_extended_jump_aarch64(inst_buff, to, return_addr);
  auto total_patch_size = inst_buff.size() * 4;

  Monkeypatcher::ExtendedJumpPage* page = nullptr;

  // There are two jumps we need to worry about for the offset
  // (actually 3 since there's also the jump back after unpatching
  //  but the requirement for that is always more relaxed than the combination
  //  of these two),
  // the jump to the stub and the jump back.
  // The jump to the stub has offset `stub - syscall` and the jump back has offset
  // `syscall + 4 - (stub + ret_idx * 4)`
  // We need to make sure both are within the offset range so
  // * aarch64_b_min_offset <= stub - syscall <= aarch64_b_max_offset
  // * aarch64_b_min_offset <= syscall + 4 - (stub + ret_idx * 4) <= aarch64_b_max_offset
  // or
  // * aarch64_b_min_offset <= stub - syscall <= aarch64_b_max_offset
  // * -aarch64_b_max_offset + 4 - ret_idx * 4 <= stub - syscall <= -aarch64_b_min_offset + 4 - ret_idx * 4

  int64_t patch_offset_min = std::max(aarch64_b_min_offset,
                                      -aarch64_b_max_offset + 4 - int(ret_idx) * 4);
  int64_t patch_offset_max = std::min(aarch64_b_max_offset,
                                      -aarch64_b_min_offset + 4 - int(ret_idx) * 4);
  for (auto& p : pages) {
    remote_ptr<uint8_t> page_jump_start = p.addr + p.allocated;
    int64_t offset = page_jump_start - svc_ip;
    if (offset <= patch_offset_max && offset >= patch_offset_min &&
        p.allocated + total_patch_size <= page_size()) {
      page = &p;
      break;
    }
  }

  if (!page) {
    // We're looking for a gap of three pages --- one page to allocate and
    // a page on each side as a guard page.
    uint32_t required_space = 3 * page_size();
    remote_ptr<void> free_mem =
        t->vm()->find_free_memory(t, required_space,
                                  // Find free space after the patch site.
                                  t->vm()->mapping_of(svc_ip).map.start());
    if (!free_mem) {
      LOG(debug) << "Can't find free memory anywhere after the jump";
      return nullptr;
    }

    remote_ptr<uint8_t> addr = (free_mem + page_size()).cast<uint8_t>();
    int64_t offset = addr - svc_ip;
    if (offset > patch_offset_max || offset < patch_offset_min) {
      LOG(debug) << "Can't find space close enough for the jump";
      return nullptr;
    }

    {
      AutoRemoteSyscalls remote(t);
      int prot = PROT_READ | PROT_EXEC;
      int flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
      auto ret = remote.infallible_mmap_syscall_if_alive(addr, page_size(), prot, flags, -1, 0);
      if (!ret) {
        /* Tracee died */
        return nullptr;
      }
      KernelMapping recorded(addr, addr + page_size(), string(),
                             KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                             prot, flags);
      t->vm()->map(t, addr, page_size(), prot, flags, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                   &recorded);
      t->vm()->mapping_flags_of(addr) |= AddressSpace::Mapping::IS_PATCH_STUBS;
      t->trace_writer().write_mapped_region(t, recorded, recorded.fake_stat(),
                                            recorded.fsname(),
                                            vector<TraceRemoteFd>(),
                                            TraceWriter::PATCH_MAPPING);
    }

    pages.push_back(Monkeypatcher::ExtendedJumpPage(addr));
    page = &pages.back();
  }

  remote_ptr<uint8_t> jump_addr = page->addr + page->allocated;

  const uint64_t reverse_jump_addr = jump_addr.as_int() + ret_idx * 4;
  const int64_t reverse_offset = int64_t(return_addr - reverse_jump_addr);
  const uint32_t offset_imm26 = (reverse_offset >> 2) & 0x03ffffff;
  inst_buff[ret_idx] = 0x14000000 | offset_imm26;

  page->allocated += total_patch_size;

  return jump_addr;
}

constexpr int64_t MAX_AARCH64_JUMP_DELTA = ((1 << 25) - 1) * 4;
constexpr int64_t MIN_AARCH64_JUMP_DELTA = (1 << 25) * -4;
const uint32_t SC_AARCH64_STUB[] = {
0xa9bf23e1, 	// stp	x1, x8, [sp, #-16]!
0xa9bf47f0, 	// stp	x16, x17, [sp, #-16]!
0xd53b4201, 	// mrs	x1, nzcv
0x52800028, 	// mov	w8, #0x1
0x52809411, 	// mov	w17, #0x4a0
0x72ae0031, 	// movk	w17, #0x7001, lsl #16
0xf8280230, 	// ldadd	x8, x16, [x17]
0xa9404630, 	// ldp	x16, x17, [x17]
0xeb11021f, 	// cmp	x16, x17
0x5400004b, 	// b.lt	jump_label (jump forward 8 bytes)
0xd4200000, 	// brk	#0x0
// jump_label:
0xd51b4201, 	// msr	nzcv, x1
0xa8c147f0, 	// ldp	x16, x17, [sp], #16
0xa8c123e1, 	// ldp	x1, x8, [sp], #16
0x00000000, 	// udf	#0
0x14000000, 	// b	#0
0x14000000, 	// b	#0
};
constexpr size_t SC_AARCH64_STUB_LEN = sizeof(SC_AARCH64_STUB)/sizeof(uint32_t);
constexpr size_t SC_AARCH64_STUB_SIZE_BYTES = sizeof(SC_AARCH64_STUB);

enum cond_branch_type {
  BTYPE_UNKNOWN,
  BCOND_BCCOND,
  CBZ_CBNZ,
  TBZ_TBNZ,
};

constexpr int64_t MAX_X64_JUMP_IMM = INT32_MAX;
constexpr int64_t MIN_X64_JUMP_IMM = INT32_MIN;
// SC prefix means "Software Counter"
const uint8_t SC_X64_PRELUDE[] = {
  0x48, 0x89, 0x24, 0x25, 0xd8, 0x10, 0x00,
  0x70, // mov    QWORD PTR ds:0x700010d8,rsp
  0x48, 0xc7, 0xc4, 0xd8, 0x10, 0x00, 0x70, // mov    rsp,0x700010d8
  0x9c,                                     // pushf
  0x41, 0x53,                               // push   r11
  0xf0, 0x48, 0xff, 0x04, 0x25, 0x90, 0x10, 0x00,
  0x70, // lock inc QWORD PTR ds:0x70001090
  0x4c, 0x8b, 0x1c, 0x25, 0x90, 0x10, 0x00,
  0x70, // mov    r11,QWORD PTR ds:0x70001090
  0x4c, 0x3b, 0x1c, 0x25, 0x98, 0x10, 0x00,
  0x70,       // cmp    r11,QWORD PTR ds:0x70001098
  0x7c, 0x01, // jl short <<JUMP_LABEL>>
  0xcc,       // int3
  // <<JUMP_LABEL>>:
  0x45, 0x31, 0xdb, // xor    r11d,r11d
  0x41, 0x5b,       // pop    r11
  0x9d,             // popf
  0x48, 0x8b, 0x24, 0x25, 0xd8, 0x10, 0x00,
  0x70, // mov    rsp,QWORD PTR ds:0x700010d8
};
constexpr size_t SC_X64_PRELUDE_SIZE_BYTES = sizeof(SC_X64_PRELUDE);

// How many bytes into the mapped space do the normal stubs start ?
const size_t SC_MMAP_FIRST_STUB_START_OFFSET = 0;

template <typename Arch>
static bool jump_doable_arch(const uint64_t, const uint64_t, int64_t,
                             const uint64_t, const size_t, int64_t&, int64_t&) {
  assert(false && "Not implemented for platform");
  __builtin_unreachable();
}

template <>
// in x86 the jump "from" address is relative to the start of the next
// instruction
bool jump_doable_arch<X64Arch>(
    const uint64_t stub_landing_addr, const uint64_t cond_jump_from_addr,
    // important the delta is 64 bits
    const int64_t cond_jump_actual_delta, const uint64_t stub_area_end,
    const size_t stub_size_bytes,
    int64_t& from_stub_jump_back_to_next_instr_imm,
    int64_t& from_stub_jump_back_to_orig_jump_target_instr_imm) {
  uint64_t stub_end = stub_landing_addr + stub_size_bytes;
  if (!(stub_end <= stub_area_end)) {
    return false;
  }

  // +5 and not +6 because the conditional jump will be replaced by
  // an unconditional jump + nop
  int64_t to_stub_jump_imm = stub_landing_addr - (cond_jump_from_addr + 5);
  if (!(MIN_X64_JUMP_IMM <= to_stub_jump_imm &&
        to_stub_jump_imm <= MAX_X64_JUMP_IMM)) {
    return false;
  }

  // 5 byte relative unconditional jump that is just behind another 5 byte
  // relative jump
  from_stub_jump_back_to_next_instr_imm =
      (cond_jump_from_addr + 6) - (stub_landing_addr + stub_size_bytes - 5);
  if (!(MIN_X64_JUMP_IMM <= from_stub_jump_back_to_next_instr_imm &&
        from_stub_jump_back_to_next_instr_imm <= MAX_X64_JUMP_IMM)) {
    return false;
  }

  // 5 byte relative jump that is the last instruction
  from_stub_jump_back_to_orig_jump_target_instr_imm =
      (cond_jump_from_addr + cond_jump_actual_delta) -
      (stub_landing_addr + stub_size_bytes);
  if (!(MIN_X64_JUMP_IMM <= from_stub_jump_back_to_orig_jump_target_instr_imm &&
        from_stub_jump_back_to_orig_jump_target_instr_imm <=
            MAX_X64_JUMP_IMM)) {
    return false;
  }

  return true;
}

template <>
bool jump_doable_arch<ARM64Arch>(
    const uint64_t stub_landing_addr, const uint64_t cond_jump_from_addr,
    int64_t cond_jump_delta, const uint64_t stub_area_end,
    const size_t stub_size_bytes,
    int64_t& from_stub_jump_back_to_next_instr_delta,
    int64_t& from_stub_jump_back_to_original_jump_target_delta) {
  uint64_t stub_end = stub_landing_addr + stub_size_bytes;
  if (!(stub_end <= stub_area_end)) {
    return false;
  }

  int64_t to_stub_jump_delta = stub_landing_addr - cond_jump_from_addr;
  if (!(MIN_AARCH64_JUMP_DELTA <= to_stub_jump_delta &&
        to_stub_jump_delta <= MAX_AARCH64_JUMP_DELTA)) {
    return false;
  }

  from_stub_jump_back_to_next_instr_delta =
      (cond_jump_from_addr + 4) - (stub_landing_addr + stub_size_bytes - 8);
  if (!(MIN_AARCH64_JUMP_DELTA <= from_stub_jump_back_to_next_instr_delta &&
        from_stub_jump_back_to_next_instr_delta <= MAX_AARCH64_JUMP_DELTA)) {
    return false;
  }

  from_stub_jump_back_to_original_jump_target_delta =
      (cond_jump_from_addr + cond_jump_delta) -
      (stub_landing_addr + stub_size_bytes - 4);
  if (!(MIN_AARCH64_JUMP_DELTA <=
            from_stub_jump_back_to_original_jump_target_delta &&
        from_stub_jump_back_to_original_jump_target_delta <=
            MAX_AARCH64_JUMP_DELTA)) {
    return false;
  }

  return true;
}

static void could_not_find_nearby_mem_for_stub_area(
    RecordTask& t, remote_ptr<void> map_addr) {
  LOG(warn) << "  Can't find space close enough for software counter "
               "jump stub before/after: "
            << map_addr << " for tid: " << t.tid;
  t.session().accumulate_no_near_stub_mem();
}

static bool jump_doable(
    const SupportedArch arch, const uint64_t stub_landing_addr,
    const uint64_t cond_jump_from_addr, int64_t cond_jump_delta,
    const uint64_t stub_area_end, const size_t stub_size_bytes,
    int64_t& from_stub_jump_back_to_next_instr_imm,
    int64_t& from_stub_jump_back_to_orig_jump_target_instr_imm) {
  RR_ARCH_FUNCTION(jump_doable_arch, arch, stub_landing_addr,
                   cond_jump_from_addr, cond_jump_delta, stub_area_end,
                   stub_size_bytes, from_stub_jump_back_to_next_instr_imm,
                   from_stub_jump_back_to_orig_jump_target_instr_imm);
}

// Get a stub area from existing pool of stub areas or creates a new stub area
// if the old areas are full or out of range.
//
// Returns nullptr if that could not be accomplished
static Monkeypatcher::JumpStubArea* get_or_create_in_range_stub_area(
    RecordTask& t, vector<Monkeypatcher::JumpStubArea>& stub_areas,
    size_t& last_used_stub_area, const remote_ptr<uint8_t> cond_jump_from_addr,
    const int64_t cond_jump_actual_delta,
    int64_t& from_stub_jump_back_to_next_instr_imm,
    int64_t& from_stub_jump_back_to_orig_jump_target_instr_imm,
    const size_t stub_size_bytes) {
  const size_t len = stub_areas.size();
  Monkeypatcher::JumpStubArea* found_stub_area = nullptr;
  SupportedArch arch = t.arch();

  // To speed things up, try the last used stub area
  // It is likely to be the same
  if (last_used_stub_area < len) {
    auto& area = stub_areas[last_used_stub_area];
    const uint64_t stub_landing_addr =
        area.jump_area_start.as_int() + area.allocated_bytes;
    const uint64_t stub_area_end =
        area.jump_area_start.as_int() + area.jump_area_size;
    if (jump_doable(arch, stub_landing_addr, cond_jump_from_addr.as_int(),
                    cond_jump_actual_delta, stub_area_end, stub_size_bytes,
                    from_stub_jump_back_to_next_instr_imm,
                    from_stub_jump_back_to_orig_jump_target_instr_imm)) {
      found_stub_area = &area;
      return found_stub_area;
    }
  }

  for (size_t i = 0; i < len; i++) {
    auto& area = stub_areas[i];
    const uint64_t stub_landing_addr =
        area.jump_area_start.as_int() + area.allocated_bytes;
    const uint64_t stub_area_end =
        area.jump_area_start.as_int() + area.jump_area_size;
    if (jump_doable(arch, stub_landing_addr, cond_jump_from_addr.as_int(),
                    cond_jump_actual_delta, stub_area_end, stub_size_bytes,
                    from_stub_jump_back_to_next_instr_imm,
                    from_stub_jump_back_to_orig_jump_target_instr_imm)) {
      found_stub_area = &area;
      last_used_stub_area = i;
      return found_stub_area;
    }
  }

  // If page size = 4K then 32 pages
  // If page size = 16K then 8 pages
  // If page size = 64K then 2 pages
  // ... and 2 guard pages on either side
  const uint32_t num_stub_pages = SC_MMAP_AREA / page_size();
  const uint32_t required_space = (2 + num_stub_pages) * page_size();
  const uint32_t non_guard_space = required_space - 2 * page_size();
  const auto map_addr = t.vm()->mapping_of(cond_jump_from_addr).map.start();

  // Find free space before the patch site.
  const remote_ptr<void> free_mem_before =
      t.vm()->find_free_memory_before(&t, required_space, map_addr);

  remote_ptr<uint8_t> map_start;
  if (free_mem_before) {
    // skip the initial page, its a guard
    map_start = (free_mem_before + page_size()).cast<uint8_t>();
    const uint64_t stub_landing_addr =
        map_start.as_int() + SC_MMAP_FIRST_STUB_START_OFFSET;
    const uint64_t stub_area_end = map_start.as_int() + non_guard_space;
    if (!jump_doable(arch, stub_landing_addr, cond_jump_from_addr.as_int(),
                     cond_jump_actual_delta, stub_area_end, stub_size_bytes,
                     from_stub_jump_back_to_next_instr_imm,
                     from_stub_jump_back_to_orig_jump_target_instr_imm)) {
      // Find free space after the patch site.
      const remote_ptr<void> free_mem_after =
          t.vm()->find_free_memory(&t, required_space, map_addr);
      if (free_mem_after) {
        // skip the initial page, its a guard
        map_start = (free_mem_after + page_size()).cast<uint8_t>();
        const uint64_t stub_landing_addr =
            map_start.as_int() + SC_MMAP_FIRST_STUB_START_OFFSET;
        const uint64_t stub_area_end = map_start.as_int() + non_guard_space;
        if (!jump_doable(arch, stub_landing_addr, cond_jump_from_addr.as_int(),
                         cond_jump_actual_delta, stub_area_end, stub_size_bytes,
                         from_stub_jump_back_to_next_instr_imm,
                         from_stub_jump_back_to_orig_jump_target_instr_imm)) {
          could_not_find_nearby_mem_for_stub_area(t, map_addr);
          return nullptr;
        }
      } else {
        could_not_find_nearby_mem_for_stub_area(t, map_addr);
        return nullptr;
      }
    }
  } else {
    // Find free space after the patch site.
    const remote_ptr<void> free_mem_after =
        t.vm()->find_free_memory(&t, required_space, map_addr);
    if (free_mem_after) {
      // skip the initial page, its a guard
      map_start = (free_mem_after + page_size()).cast<uint8_t>();
      const uint64_t stub_landing_addr =
          map_start.as_int() + SC_MMAP_FIRST_STUB_START_OFFSET;
      const uint64_t stub_area_end = map_start.as_int() + non_guard_space;
      if (!jump_doable(arch, stub_landing_addr, cond_jump_from_addr.as_int(),
                       cond_jump_actual_delta, stub_area_end, stub_size_bytes,
                       from_stub_jump_back_to_next_instr_imm,
                       from_stub_jump_back_to_orig_jump_target_instr_imm)) {
        could_not_find_nearby_mem_for_stub_area(t, map_addr);
        return nullptr;
      }
    } else {
      could_not_find_nearby_mem_for_stub_area(t, map_addr);
      return nullptr;
    }
  }

  const bool ret = t.vm()->map_software_counter_jump_stub_area(t, map_start,
                                                               non_guard_space);
  if (!ret) {
    FATAL() << "Could not map software counter jump stub area at:" << map_start;
    return nullptr;
  }

  stub_areas.push_back(
      Monkeypatcher::JumpStubArea(map_start, num_stub_pages * page_size()));
  found_stub_area = &stub_areas.back();
  found_stub_area->allocated_bytes = SC_MMAP_FIRST_STUB_START_OFFSET;

  // statistics
  t.session().accumulate_sc_jump_areas_mmaped();
  const size_t additional_capacity =
      (found_stub_area->jump_area_size - found_stub_area->allocated_bytes) /
      stub_size_bytes;
  t.session().accumulate_sc_jump_areas_stub_capacity(additional_capacity);
  return found_stub_area;
}

static remote_ptr<uint32_t> allocate_software_counter_stub_aarch64(
    RecordTask& t, vector<Monkeypatcher::JumpStubArea>& stub_areas,
    size_t& last_used_stub_area, const uint32_t cond_instr,
    const remote_ptr<uint32_t> cond_jump_from_addr,
    std::vector<uint32_t>& inst_buff) {
  int64_t cond_jump_delta;
  auto cond_type = BTYPE_UNKNOWN;
  if (cond_instr >> 24 == 0x54) {
    cond_type = BCOND_BCCOND;
    // LOG(debug) << "Found b.cond/bc.cond instruction: " << HEX(cond_instr)
    //            << " at: " << cond_instr_addr;
    cond_jump_delta = (cond_instr >> 5) & 0x7'FFFF;
    // sign extend
    if (cond_jump_delta & (1 << 18)) {
      cond_jump_delta = (cond_jump_delta | 0xFFFF'FFFF'FFF8'0000UL) << 2;
    } else {
      cond_jump_delta <<= 2;
    }
  } else if (((cond_instr >> 24) & 0b0111'1110) == 0b0011'0100) {
    cond_type = CBZ_CBNZ;
    // LOG(debug) << "Found cbz/cbnz instruction: " << HEX(cond_instr)
    //            << " at: " << cond_instr_addr;
    cond_jump_delta = (cond_instr >> 5) & 0x7FFFF;
    // sign extend
    if (cond_jump_delta & (1 << 18)) {
      cond_jump_delta = (cond_jump_delta | 0xFFFF'FFFF'FFF8'0000UL) << 2;
    } else {
      cond_jump_delta <<= 2;
    }
  } else if (((cond_instr >> 24) & 0b0111'1110) == 0b0011'0110) {
    cond_type = TBZ_TBNZ;
    // LOG(debug) << "Found tbz/tbnz instruction: " << HEX(cond_instr)
    //            << " at: " << cond_instr_addr;
    cond_jump_delta = (cond_instr >> 5) & 0x3FFF;
    // sign extend
    if (cond_jump_delta & (1 << 13)) {
      cond_jump_delta = (cond_jump_delta | 0xFFFF'FFFF'FFFF'C000UL) << 2;
    } else {
      cond_jump_delta <<= 2;
    }
  } else {
    ASSERT(
        &t,
        false &&
            "Only b.cond, bc.cond, cbz, cbnz, tbz, tbnz supported on aarch64");
    __builtin_unreachable();
  }

  int64_t from_stub_jump_back_to_next_instr_delta = 0;
  int64_t from_stub_jump_back_to_original_jump_target_delta = 0;
  Monkeypatcher::JumpStubArea* found_stub_area =
      get_or_create_in_range_stub_area(
          t, stub_areas, last_used_stub_area,
          cond_jump_from_addr.cast<uint8_t>(), cond_jump_delta,
          from_stub_jump_back_to_next_instr_delta,
          from_stub_jump_back_to_original_jump_target_delta,
          SC_AARCH64_STUB_SIZE_BYTES);

  if (!found_stub_area) {
    return nullptr;
  }

  // Need to fill in first three instruction
  const uint32_t offset_imm26 =
      (from_stub_jump_back_to_original_jump_target_delta >> 2) & 0x03ff'ffff;
  // 0x14000000 is b #0
  inst_buff[SC_AARCH64_STUB_LEN - 1] = 0x14000000 | offset_imm26;

  const uint32_t offset_imm26_2 =
      (from_stub_jump_back_to_next_instr_delta >> 2) & 0x03ff'ffff;
  // 0x14000000 is b #0
  inst_buff[SC_AARCH64_STUB_LEN - 2] = 0x14000000 | offset_imm26_2;

  // b.cond and bc.cond
  if (cond_type == BCOND_BCCOND) {
    uint32_t consistent_bit_and_cond_code = cond_instr & 0x1f;
    // represents a jump forward of 8 bytes
    uint32_t imm19 = (0x8 >> 2) << 5;
    inst_buff[SC_AARCH64_STUB_LEN - 3] =
        0x54000000 | imm19 | consistent_bit_and_cond_code;
  } else if (cond_type == CBZ_CBNZ) {
    // represents a jump forward of 8 bytes
    uint32_t imm19 = (0x8 >> 2) << 5;
    // zero out immediate and then add in the imm19 branch offset
    inst_buff[SC_AARCH64_STUB_LEN - 3] = (cond_instr & 0xFF00001F) | imm19;
  } else if (cond_type == TBZ_TBNZ) {
    // represents a jump forward of 8 bytes
    uint32_t imm14 = (0x8 >> 2) << 5;
    // zero out immediate and then add in the imm14 branch offset
    inst_buff[SC_AARCH64_STUB_LEN - 3] = (cond_instr & 0xFFF8001F) | imm14;
  } else {
    // Only support b.cond, bc.cond, cbz, cbnz, tbz, tbnz right now
    ASSERT(&t, false);
  }

  const auto jump_addr =
      found_stub_area->jump_area_start + found_stub_area->allocated_bytes;
  found_stub_area->allocated_bytes += SC_AARCH64_STUB_SIZE_BYTES;

  t.session().accumulate_sc_jump_stubs_allocated();
  return jump_addr.cast<uint32_t>();
}

static remote_ptr<uint8_t> allocate_software_counter_stub_x64(
    RecordTask& t, vector<Monkeypatcher::JumpStubArea>& stub_areas,
    size_t& last_used_stub_area, const remote_ptr<uint8_t> cond_jump_from_addr,
    const PatchData& patch_data, vector<uint8_t>& stub_buff,
    vector<uint8_t>& instr_patch) {
  const int64_t cond_jump_actual_delta = patch_data.actual_delta;
  constexpr size_t stub_size_bytes =
      SC_X64_PRELUDE_SIZE_BYTES /* counting prelude */ + 6 /* conditional jump */
      + 5 /* unconditional branch */ + 5 /* another unconditional branch */;

  int64_t from_stub_jump_back_to_next_instr_imm = 0;
  int64_t from_stub_jump_back_to_orig_jump_target_instr_imm = 0;
  Monkeypatcher::JumpStubArea* found_stub_area =
      get_or_create_in_range_stub_area(
          t, stub_areas, last_used_stub_area, cond_jump_from_addr,
          cond_jump_actual_delta, from_stub_jump_back_to_next_instr_imm,
          from_stub_jump_back_to_orig_jump_target_instr_imm, stub_size_bytes);
  const int32_t from_stub_jump_back_to_next_instr_imm32 =
      from_stub_jump_back_to_next_instr_imm;
  const int32_t from_stub_jump_back_to_orig_jump_target_instr_imm32 =
      from_stub_jump_back_to_orig_jump_target_instr_imm;

  if (!found_stub_area) {
    return nullptr;
  }

  {
    // counting prelude
    stub_buff.resize(SC_X64_PRELUDE_SIZE_BYTES);

    // conditional branch instruction, jump forward 5 bytes
    stub_buff.push_back(patch_data.data[0]); // opcode byte 1
    stub_buff.push_back(patch_data.data[1]); // opcode byte 2
    const int32_t five = 5;
    const auto* p_five = &five;
    stub_buff.insert(stub_buff.end(), (char*)p_five, (char*)(p_five + 1));

    // jmp to next instruction in original instruction stream
    stub_buff.push_back(0xe9); // jmp rel32
    const auto p_next = &from_stub_jump_back_to_next_instr_imm32;
    stub_buff.insert(stub_buff.end(), (char*)p_next, (char*)(p_next + 1));

    // jmp to successful jump target in original instruction stream
    stub_buff.push_back(0xe9); // jmp rel32
    const auto p_target = &from_stub_jump_back_to_orig_jump_target_instr_imm32;
    stub_buff.insert(stub_buff.end(), (char*)p_target, (char*)(p_target + 1));
    ASSERT(&t, stub_buff.size() == stub_size_bytes)
        << stub_buff.size() << " != " << stub_size_bytes;
  }
  const auto stub_landing_addr =
      found_stub_area->jump_area_start + found_stub_area->allocated_bytes;
  {
    instr_patch.clear();
    instr_patch.push_back(0xe9); // jmp rel32
    // +5 and not +6 because this was originally a conditional jump
    // but now it is an unconditional jump + nop
    const int32_t delta_to_stub_landing_imm =
        stub_landing_addr.as_int() - (cond_jump_from_addr.as_int() + 5);
    const auto p_next = &delta_to_stub_landing_imm;
    instr_patch.insert(instr_patch.end(), (char*)p_next, (char*)(p_next + 1));
    instr_patch.push_back(0x90); // nop
    ASSERT(&t, instr_patch.size() == 6);
  }

  found_stub_area->allocated_bytes += stub_buff.size();

  t.session().accumulate_sc_jump_stubs_allocated();
  return stub_landing_addr;
}

bool Monkeypatcher::is_jump_stub_instruction(remote_code_ptr ip, bool include_safearea) {
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs.upper_bound(pp);
  if (it == syscallbuf_stubs.begin()) {
    return false;
  }
  --it;
  auto begin = it->first;
  auto end = begin + it->second.size;
  if (!include_safearea) {
    begin += it->second.safe_prefix;
    end -= it->second.safe_suffix;
  }
  return begin <= pp && pp < end;
}

remote_code_ptr Monkeypatcher::get_jump_stub_exit_breakpoint(remote_code_ptr ip,
                                                             RecordTask *t) {
  if (t->arch() != aarch64) {
    return nullptr;
  }
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs.upper_bound(pp);
  if (it == syscallbuf_stubs.begin()) {
    return nullptr;
  }
  --it;
  auto bp = it->first + it->second.size - it->second.safe_suffix;
  if (pp == bp || pp == bp - 4) {
    return remote_code_ptr(bp.as_int());
  }
  return nullptr;
}

static bool hook_can_ignore_interfering_branches(const syscall_patch_hook& hook, size_t jump_patch_size) {
  return hook.patch_region_length >= jump_patch_size &&
    (hook.flags & (PATCH_IS_MULTIPLE_INSTRUCTIONS | PATCH_IS_NOP_INSTRUCTIONS)) == PATCH_IS_NOP_INSTRUCTIONS;
}

/**
 * Some functions make system calls while storing local variables in memory
 * below the stack pointer. We need to decrement the stack pointer by
 * some "safety zone" amount to get clear of those variables before we make
 * a call instruction. So, we allocate a stub per patched callsite, and jump
 * from the callsite to the stub. The stub decrements the stack pointer,
 * calls the appropriate syscall hook function, reincrements the stack pointer,
 * and jumps back to immediately after the patched callsite.
 *
 * It's important that gdb stack traces work while a thread is stopped in the
 * syscallbuf code. To ensure that the above manipulations don't foil gdb's
 * stack walking code, we add CFI data to all the stubs. To ease that, the
 * stubs are written in assembly and linked into the preload library.
 *
 * On x86-64 with ASLR, we need to be able to patch a call to a stub from
 * sites more than 2^31 bytes away. We only have space for a 5-byte jump
 * instruction. So, we allocate "extender pages" --- pages of memory within
 * 2GB of the patch site, that contain the stub code. We don't really need this
 * on x86, but we do it there too for consistency.
 *
 * If fake_syscall_number > 0 then we'll ensure AX is set to that number
 * by the stub code.
 */
template <typename JumpPatch, typename ExtendedJumpPatch, typename FakeSyscallExtendedJumpPatch>
static bool patch_syscall_with_hook_x86ish(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook,
                                           remote_code_ptr ip_of_instruction,
                                           size_t instruction_length,
                                           uint32_t fake_syscall_number) {
  size_t patch_region_size = instruction_length + hook.patch_region_length;
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  remote_ptr<uint8_t> jump_patch_start = ip_of_instruction.to_data_ptr<uint8_t>();
  if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
    jump_patch_start -= hook.patch_region_length;
  }
  remote_ptr<uint8_t> jump_patch_end = jump_patch_start + JumpPatch::size;
  remote_ptr<uint8_t> return_addr =
    jump_patch_start + patch_region_size;

  remote_ptr<uint8_t> extended_jump_start;
  if (fake_syscall_number) {
    extended_jump_start = allocate_extended_jump_x86ish<FakeSyscallExtendedJumpPatch>(
        t, patcher.extended_jump_pages, jump_patch_end);
  } else {
    extended_jump_start = allocate_extended_jump_x86ish<ExtendedJumpPatch>(
          t, patcher.extended_jump_pages, jump_patch_end);
  }
  if (extended_jump_start.is_null()) {
    return false;
  }

  if (fake_syscall_number) {
    uint8_t stub_patch[FakeSyscallExtendedJumpPatch::size];
    substitute_extended_jump<FakeSyscallExtendedJumpPatch>(stub_patch,
                                                extended_jump_start.as_int(),
                                                return_addr.as_int(),
                                                hook.hook_address,
                                                fake_syscall_number);
    write_and_record_bytes(t, extended_jump_start, stub_patch);

    patcher.syscallbuf_stubs[extended_jump_start] = { &hook, FakeSyscallExtendedJumpPatch::size };
  } else {
    uint8_t stub_patch[ExtendedJumpPatch::size];
    substitute_extended_jump<ExtendedJumpPatch>(stub_patch,
                                                extended_jump_start.as_int(),
                                                return_addr.as_int(),
                                                hook.hook_address,
                                                0);
    write_and_record_bytes(t, extended_jump_start, stub_patch);

    patcher.syscallbuf_stubs[extended_jump_start] = { &hook, ExtendedJumpPatch::size };
  }

  intptr_t jump_offset = extended_jump_start - jump_patch_end;
  int32_t jump_offset32 = (int32_t)jump_offset;
  ASSERT(t, jump_offset32 == jump_offset)
      << "allocate_extended_jump_x86ish didn't work";

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  vector<uint8_t> jump_patch;
  jump_patch.resize(patch_region_size, NOP);
  if (hook_can_ignore_interfering_branches(hook, JumpPatch::size)) {
    // If the preceding instruction is long enough to contain the entire jump,
    // and is a nop, replace the original instruction by a jump back to the
    // start of the patch region. This allows us to ignore (likely spurious,
    // but nevertheless), interfering branches, because whether we jump to the
    // instruction or the start of the patch region, the effect is the same.
    jump_patch[patch_region_size-2] = 0xeb; // jmp rel
    jump_patch[patch_region_size-1] = (int8_t)-patch_region_size;
  }
  JumpPatch::substitute(jump_patch.data(), jump_offset32);
  bool ok = true;
  write_and_record_bytes(t, jump_patch_start, jump_patch.size(), jump_patch.data(), &ok);
  if (!ok) {
    LOG(warn) << "Couldn't write patch; errno=" << errno;
  }
  return ok;
}

template <>
bool patch_syscall_with_hook_arch<X86Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook,
                                           remote_code_ptr ip_of_instruction,
                                           size_t instruction_length,
                                           uint32_t fake_syscall_number) {
  return patch_syscall_with_hook_x86ish<X86SysenterVsyscallSyscallHook,
                                        X86SyscallStubExtendedJump,
                                        X86TrapInstructionStubExtendedJump>(patcher, t,
                                                                            hook,
                                                                            ip_of_instruction,
                                                                            instruction_length,
                                                                            fake_syscall_number);
}

template <>
bool patch_syscall_with_hook_arch<X64Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook,
                                           remote_code_ptr ip_of_instruction,
                                           size_t instruction_length,
                                           uint32_t fake_syscall_number) {
  return patch_syscall_with_hook_x86ish<X64JumpMonkeypatch,
                                        X64SyscallStubExtendedJump,
                                        X64TrapInstructionStubExtendedJump>(patcher, t,
                                                                            hook,
                                                                            ip_of_instruction,
                                                                            instruction_length,
                                                                            fake_syscall_number);
}

template <>
bool patch_syscall_with_hook_arch<ARM64Arch>(Monkeypatcher& patcher,
                                             RecordTask *t,
                                             const syscall_patch_hook &hook,
                                             remote_code_ptr,
                                             size_t,
                                             uint32_t) {
  Registers r = t->regs();
  remote_ptr<uint8_t> svc_ip = r.ip().to_data_ptr<uint8_t>();
  std::vector<uint32_t> inst_buff;

  remote_ptr<uint8_t> extended_jump_start =
    allocate_extended_jump_aarch64(
      t, patcher.extended_jump_pages, svc_ip, hook.hook_address, inst_buff);
  if (extended_jump_start.is_null()) {
    return false;
  }
  LOG(debug) << "Allocated stub size " << inst_buff.size() * sizeof(uint32_t)
             << " bytes at " << extended_jump_start << " for syscall at "
             << svc_ip;

  auto total_patch_size = inst_buff.size() * 4;
  write_and_record_bytes(t, extended_jump_start, total_patch_size, &inst_buff[0]);

  patcher.syscallbuf_stubs[extended_jump_start] = {
    &hook, total_patch_size,
    /**
     * safe_prefix:
     * We have not modified any registers yet in the first two instructions.
     * More importantly, we may bail out and return to user code without
     * hitting the breakpoint in syscallbuf
     */
    2 * 4,
    /**
     * safe_suffix:
     * We've returned from syscallbuf and continue execution
     * won't hit syscallbuf breakpoint
     * (this also include the 8 bytes that stores the return address)
     * Note that the 4th last instruction also belongs to the syscallbuf return path
     * However, since it is still using the scratch memory,
     * it doesn't belong to the safe area.
     * The caller needs to have special handling for that instruction.
     */
    3 * 4 + 8
  };

  intptr_t jump_offset = extended_jump_start - svc_ip;
  ASSERT(t, jump_offset <= aarch64_b_max_offset && jump_offset >= aarch64_b_min_offset)
      << "allocate_extended_jump_aarch64 didn't work";

  const uint32_t offset_imm26 = (jump_offset >> 2) & 0x03ffffff;
  const uint32_t b_inst = 0x14000000 | offset_imm26;
  bool ok = true;
  write_and_record_bytes(t, svc_ip, 4, &b_inst, &ok);
  if (!ok) {
    LOG(warn) << "Couldn't write patch; errno=" << errno;
  }
  return ok;
}


static bool patch_syscall_with_hook(Monkeypatcher& patcher, RecordTask* t,
                                    const syscall_patch_hook& hook,
                                    remote_code_ptr ip_of_instruction,
                                    size_t instruction_length,
                                    uint32_t fake_syscall_number) {
  RR_ARCH_FUNCTION(patch_syscall_with_hook_arch, t->arch(), patcher, t, hook,
                   ip_of_instruction, instruction_length, fake_syscall_number);
}

template <typename ExtendedJumpPatch>
static bool match_extended_jump_patch(Task* t,
  uint8_t patch[], uint64_t* return_addr, vector<uint8_t>* instruction);

template <>
bool match_extended_jump_patch<X64SyscallStubExtendedJump>(
      Task*, uint8_t patch[], uint64_t* return_addr, vector<uint8_t>* instruction) {
  uint32_t return_addr_lo, return_addr_hi;
  uint64_t jmp_target;
  if (!X64SyscallStubExtendedJump::match(patch, &return_addr_lo, &return_addr_hi, &jmp_target)) {
    return false;
  }
  *instruction = rr::syscall_instruction(x86_64);
  *return_addr = return_addr_lo | (((uint64_t)return_addr_hi) << 32);
  return true;
}

template <>
bool match_extended_jump_patch<X64TrapInstructionStubExtendedJump>(
      Task* t, uint8_t patch[], uint64_t* return_addr, vector<uint8_t>* instruction) {
  uint32_t return_addr_lo, return_addr_hi, fake_syscall_no;
  uint64_t jmp_target;
  if (!X64TrapInstructionStubExtendedJump::match(patch, &return_addr_lo, &return_addr_hi,
                                                 &fake_syscall_no, &jmp_target)) {
    return false;
  }
  *return_addr = return_addr_lo | (((uint64_t)return_addr_hi) << 32);
  if ((int)fake_syscall_no == t->session().syscall_number_for_rrcall_rdtsc()) {
    instruction->resize(sizeof(rdtsc_insn));
    memcpy(instruction->data(), rdtsc_insn, instruction->size());
  } else {
    ASSERT(t, false) << "Unknown fake-syscall number " << fake_syscall_no;
  }
  return true;
}

template <>
bool match_extended_jump_patch<X86SyscallStubExtendedJump>(
      Task*, uint8_t patch[], uint64_t* return_addr, vector<uint8_t>* instruction) {
  uint32_t return_addr_32, jmp_target_relative;
  if (!X86SyscallStubExtendedJump::match(patch, &return_addr_32, &jmp_target_relative)) {
    return false;
  }
  *return_addr = return_addr_32;
  *instruction = rr::syscall_instruction(x86);
  return true;
}

template <typename ReplacementPatch>
static void substitute_replacement_patch(uint8_t *buffer, uint64_t patch_addr,
                                     uint64_t jmp_target);

template <>
void substitute_replacement_patch<X64SyscallStubRestore>(uint8_t *buffer, uint64_t patch_addr,
                                  uint64_t jmp_target) {
  (void)patch_addr;
  X64SyscallStubRestore::substitute(buffer, jmp_target);
}

template <>
void substitute_replacement_patch<X86SyscallStubRestore>(uint8_t *buffer, uint64_t patch_addr,
                                  uint64_t jmp_target) {
  int64_t offset =
      jmp_target -
      (patch_addr + X86SyscallStubRestore::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubRestore::substitute(buffer, (uint32_t)offset);
}

template <typename ExtendedJumpPatch, typename FakeSyscallExtendedJumpPatch, typename ReplacementPatch>
static void unpatch_extended_jumps(Monkeypatcher& patcher,
                                   Task* t) {
  static_assert(ExtendedJumpPatch::size < FakeSyscallExtendedJumpPatch::size,
                "If these were the same size then the logic below wouldn't work");
  for (auto patch : patcher.syscallbuf_stubs) {
    const syscall_patch_hook &hook = *patch.second.hook;
    uint8_t bytes[FakeSyscallExtendedJumpPatch::size];
    t->read_bytes_helper(patch.first, patch.second.size, bytes);
    uint64_t return_addr = 0;
    vector<uint8_t> syscall;
    if (patch.second.size == ExtendedJumpPatch::size) {
      if (!match_extended_jump_patch<ExtendedJumpPatch>(
              t, bytes, &return_addr, &syscall)) {
        ASSERT(t, false) << "Failed to match extended jump patch at " << patch.first;
        return;
      }
    } else if (patch.second.size == FakeSyscallExtendedJumpPatch::size) {
      if (!match_extended_jump_patch<FakeSyscallExtendedJumpPatch>(
              t, bytes, &return_addr, &syscall)) {
        ASSERT(t, false) << "Failed to match trap-instruction extended jump patch at " << patch.first;
        return;
      }
    } else {
      ASSERT(t, false) << "Unknown patch size " << patch.second.size;
    }

    // Replace with
    //  extended_jump:
    //    <syscall> (unless PATCH_SYSCALL_INSTRUCTION_IS_LAST)
    //    <original bytes>
    //    <syscall> (if PATCH_SYSCALL_INSTRUCTION_IS_LAST)
    //    jmp *(return_addr)
    // As long as there are not relative branches or anything, this should
    // always be correct.
    size_t new_patch_size = hook.patch_region_length + syscall.size() + ReplacementPatch::size;
    ASSERT(t, new_patch_size <= sizeof(bytes));
    uint8_t* ptr = bytes;
    if (!(hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST)) {
      memcpy(ptr, syscall.data(), syscall.size());
      ptr += syscall.size();
    }
    memcpy(ptr, hook.patch_region_bytes, hook.patch_region_length);
    ptr += hook.patch_region_length;
    if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
      memcpy(ptr, syscall.data(), syscall.size());
      ptr += syscall.size();
    }
    substitute_replacement_patch<ReplacementPatch>(ptr,
      patch.first.as_int() + hook.patch_region_length + syscall.size(), return_addr);
    t->write_bytes_helper(patch.first, new_patch_size, bytes);
  }
}

template <typename Arch>
static void unpatch_syscalls_arch(Monkeypatcher &patcher, Task *t);

template <>
void unpatch_syscalls_arch<X86Arch>(Monkeypatcher &patcher, Task *t) {
  // There is no 32-bit equivalent to X64TrapInstructionStubExtendedJump.
  // We just pass the X64TrapInstructionStubExtendedJump; its length
  // will never match any jump stub for 32-bit.
  return unpatch_extended_jumps<X86SyscallStubExtendedJump,
                                X64TrapInstructionStubExtendedJump,
                                X86SyscallStubRestore>(patcher, t);
}

template <>
void unpatch_syscalls_arch<X64Arch>(Monkeypatcher &patcher, Task *t) {
  return unpatch_extended_jumps<X64SyscallStubExtendedJump,
                                X64TrapInstructionStubExtendedJump,
                                X64SyscallStubRestore>(patcher, t);
}

template <>
void unpatch_syscalls_arch<ARM64Arch>(Monkeypatcher &patcher, Task *t) {
  for (auto patch : patcher.syscallbuf_stubs) {
    const syscall_patch_hook &hook = *patch.second.hook;
    std::vector<uint32_t> hook_prefix;
    uint32_t prefix_ninst;
    encode_extended_jump_aarch64(hook_prefix, hook.hook_address, 0, &prefix_ninst);
    uint32_t prefix_size = prefix_ninst * 4;
    DEBUG_ASSERT(prefix_size <= 13 * 4);
    ASSERT(t, patch.second.size >= prefix_size + 8);
    uint8_t bytes[15 * 4];
    t->read_bytes_helper(patch.first, prefix_size + 8, bytes);
    // 3rd last instruction is the one jumping back and it won't match
    if (memcmp(&hook_prefix[0], bytes, prefix_size - 3 * 4) != 0) {
      ASSERT(t, false) << "Failed to match extended jump patch at " << patch.first;
      return;
    }

    uint64_t return_addr;
    memcpy(&return_addr, &bytes[prefix_size], 8);

    uint32_t svc_inst = 0xd4000001;
    memcpy(bytes, &svc_inst, 4);

    uint64_t reverse_jump_addr = patch.first.as_int() + 4;
    int64_t reverse_offset = int64_t(return_addr - reverse_jump_addr);
    ASSERT(t, reverse_offset <= aarch64_b_max_offset &&
           reverse_offset >= aarch64_b_min_offset)
      << "Cannot encode b instruction to jump back";
    uint32_t offset_imm26 = (reverse_offset >> 2) & 0x03ffffff;
    uint32_t binst = 0x14000000 | offset_imm26;
    memcpy(&bytes[4], &binst, 4);

    t->write_bytes_helper(patch.first, 4 * 2, bytes);
  }
}

void Monkeypatcher::unpatch_syscalls_in(Task *t) {
  RR_ARCH_FUNCTION(unpatch_syscalls_arch, t->arch(), *this, t);
}

static string bytes_to_string(uint8_t* bytes, size_t size) {
  stringstream ss;
  for (size_t i = 0; i < size; ++i) {
    if (i > 0) {
      ss << ' ';
    }
    ss << HEX(bytes[i]);
  }
  return ss.str();
}

static bool task_safe_for_syscall_patching(RecordTask* t, remote_code_ptr start,
                                           remote_code_ptr end) {
  if (t->is_stopped()) {
    remote_code_ptr ip = t->ip();
    if (start <= ip && ip < end) {
      return false;
    }
  }
  for (auto& e : t->pending_events) {
    if (e.is_syscall_event()) {
      remote_code_ptr ip = e.Syscall().regs.ip();
      if (start <= ip && ip < end) {
        return false;
      }
    }
  }
  return true;
}

static bool safe_for_syscall_patching(remote_code_ptr start,
                                      remote_code_ptr end,
                                      RecordTask* exclude) {
  for (auto& p : exclude->session().tasks()) {
    RecordTask* rt = static_cast<RecordTask*>(p.second);
    if (rt != exclude && !task_safe_for_syscall_patching(rt, start, end)) {
      return false;
    }
  }
  return true;
}

bool Monkeypatcher::try_patch_vsyscall_caller(RecordTask* t, remote_code_ptr ret_addr)
{
  // Emit FLUSH_SYSCALLBUF if there's one pending.
  // We want our mmap records to be associated with the next (PATCH_SYSCALL)
  // event, not a FLUSH_SYSCALLBUF event.
  t->maybe_flush_syscallbuf();

  uint8_t bytes[X64VSyscallEntry::size];
  remote_ptr<uint8_t> patch_start = ret_addr.to_data_ptr<uint8_t>() - sizeof(bytes);
  size_t bytes_count = t->read_bytes_fallible(patch_start, sizeof(bytes), bytes);
  if (bytes_count < sizeof(bytes)) {
    return false;
  }
  uint32_t target_addr = 0;
  if (!X64VSyscallEntry::match(bytes, &target_addr)) {
    return false;
  }
  uint64_t target_addr_sext = (uint64_t)(int32_t)target_addr;
  int syscallno = 0;
  switch (target_addr_sext) {
    case 0xffffffffff600000:
      syscallno = X64Arch::gettimeofday;
      break;
    case 0xffffffffff600400:
      syscallno = X64Arch::time;
      break;
    case 0xffffffffff600800:
      syscallno = X64Arch::getcpu;
      break;
    default:
      return false;
  }
  X64VSyscallReplacement::substitute(bytes, syscallno);
  write_and_record_bytes(t, patch_start, bytes);
  LOG(debug) << "monkeypatched vsyscall caller at " << patch_start;
  return true;
}

static uint64_t jump_patch_size(SupportedArch arch)
{
  switch (arch) {
    case x86: return X86SysenterVsyscallSyscallHook::size;
    case x86_64: return X64JumpMonkeypatch::size;
    case aarch64: return 2*rr::syscall_instruction_length(arch);
    default:
      FATAL() << "Unimplemented for this architecture";
      return 0;
  }
}

const syscall_patch_hook* Monkeypatcher::find_syscall_hook(RecordTask* t,
                                                           remote_code_ptr ip,
                                                           bool entering_syscall,
                                                           size_t instruction_length,
                                                           bool &should_retry,
                                                           bool &transient_failure) {
  /* we need to inspect this many bytes before the start of the instruction,
     to find every short jump that might land after it. Conservative. */
  static const intptr_t LOOK_BACK = 0x80;
  /* we need to inspect this many bytes after the start of the instruction,
     to find every short jump that might land after it into the patch area.
     Conservative. */
  static const intptr_t LOOK_FORWARD = 15 + 15 + 0x80;
  uint8_t bytes[LOOK_BACK + LOOK_FORWARD];
  memset(bytes, 0, sizeof(bytes));

  // Split reading the code into separate reads for each page, so that if we can't read
  // from one page, we still get the data from the other page.
  ASSERT(t, sizeof(bytes) < page_size());
  remote_ptr<uint8_t> code_start = ip.to_data_ptr<uint8_t>() - LOOK_BACK;
  size_t buf_valid_start_offset = 0;
  size_t buf_valid_end_offset = sizeof(bytes);
  ssize_t first_page_bytes = min<size_t>(ceil_page_size(code_start) - code_start, sizeof(bytes));
  if (t->read_bytes_fallible(code_start, first_page_bytes, bytes) < first_page_bytes) {
    buf_valid_start_offset = first_page_bytes;
  }
  if (first_page_bytes < (ssize_t)sizeof(bytes)) {
    if (t->read_bytes_fallible(code_start + first_page_bytes, sizeof(bytes) - first_page_bytes,
                               bytes + first_page_bytes) < (ssize_t)sizeof(bytes) - first_page_bytes) {
      buf_valid_end_offset = first_page_bytes;
    }
  }

  if (buf_valid_start_offset > LOOK_BACK ||
      buf_valid_end_offset < LOOK_BACK + instruction_length) {
    ASSERT(t, false)
      << "Can't read memory containing patchable instruction, why are we trying this?";
  }

  uint8_t* following_bytes = &bytes[LOOK_BACK + instruction_length];
  size_t following_bytes_count = buf_valid_end_offset - (LOOK_BACK + instruction_length);
  size_t preceding_bytes_count = LOOK_BACK - buf_valid_start_offset;

  for (const auto& hook : syscall_hooks) {
    bool matches_hook = false;
    if ((!(hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) &&
         following_bytes_count >= hook.patch_region_length &&
         memcmp(following_bytes, hook.patch_region_bytes,
                hook.patch_region_length) == 0)) {
      matches_hook = true;
    } else if ((hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) &&
               hook.patch_region_length <= preceding_bytes_count &&
               memcmp(bytes + LOOK_BACK - hook.patch_region_length,
                      hook.patch_region_bytes,
                      hook.patch_region_length) == 0) {
      if (entering_syscall) {
        // A patch that uses bytes before the syscall can't be done when
        // entering the syscall, it must be done when exiting. So set a flag on
        // the Task that tells us to come back later.
        should_retry = true;
        LOG(debug) << "Deferring syscall patching at " << ip << " in " << t
                  << " until syscall exit.";
        return nullptr;
      }
      matches_hook = true;
    }

    if (!matches_hook) {
      continue;
    }

    if (!hook_can_ignore_interfering_branches(hook, jump_patch_size(t->arch()))) {
      // Search for a following short-jump instruction that targets an
      // instruction
      // after the syscall. False positives are OK.
      // glibc-2.23.1-8.fc24.x86_64's __clock_nanosleep needs this.
      bool found_potential_interfering_branch = false;
      for (size_t i = buf_valid_start_offset; i + 2 <= buf_valid_end_offset; ++i) {
        uint8_t b = bytes[i];
        // Check for short conditional or unconditional jump
        int branch_instruction_len = 0;
        int32_t branch_offset = 0;
        if (b == 0xeb || b == 0xe3 || (b >= 0x70 && b < 0x80)) {
          branch_instruction_len = 2;
          branch_offset = (int8_t)bytes[i + 1];
        } else if (b == 0x0f && i + 6 <= buf_valid_end_offset &&
                   (bytes[i + 1] >= 0x80 && bytes[i + 1] < 0x90)) {
          branch_instruction_len = 6;
          memcpy(&branch_offset, bytes + i + 2, 4);
        }
        if (branch_instruction_len) {
          int offset_from_instruction_end = (int)i + branch_instruction_len +
              branch_offset - (LOOK_BACK + instruction_length);
          if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
            if (hook.flags & PATCH_IS_MULTIPLE_INSTRUCTIONS) {
              found_potential_interfering_branch =
                offset_from_instruction_end <= -(ssize_t)instruction_length &&
                offset_from_instruction_end > -(ssize_t)(instruction_length + hook.patch_region_length);
            } else {
              found_potential_interfering_branch = offset_from_instruction_end == -(ssize_t)instruction_length;
            }
          } else {
            if (hook.flags & PATCH_IS_MULTIPLE_INSTRUCTIONS) {
              found_potential_interfering_branch =
                offset_from_instruction_end >= 0 && offset_from_instruction_end < hook.patch_region_length;
            } else {
              found_potential_interfering_branch = offset_from_instruction_end == 0;
            }
          }
          if (found_potential_interfering_branch) {
            LOG(debug) << "Found potential interfering branch at "
                        << ip.to_data_ptr<uint8_t>() - LOOK_BACK + i;
            break;
          }
        }
      }
      if (found_potential_interfering_branch) {
        continue;
      }
    }

    remote_code_ptr start_range, end_range;
    if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
      start_range = ip - hook.patch_region_length;
      // if a thread has its RIP at the end of our range,
      // it could be immediately after a syscall instruction that
      // will need to be restarted. Patching out that instruction will
      // prevent the kernel from restarting it. So, extend our range by
      // one byte to detect such threads.
      end_range = ip + instruction_length + 1;
    } else {
      start_range = ip;
      end_range = ip + instruction_length + hook.patch_region_length;
    }
    if (!safe_for_syscall_patching(start_range, end_range, t)) {
      transient_failure = true;
      LOG(debug)
          << "Temporarily declining to patch syscall at " << ip
          << " because a different task has its ip in the patched range";
      return nullptr;
    }
    LOG(debug) << "Trying to patch bytes "
              << bytes_to_string(
                    following_bytes,
                    min<size_t>(following_bytes_count,
                        sizeof(syscall_patch_hook::patch_region_bytes)));

    return &hook;
  }

  LOG(debug) << "Failed to find a syscall hook for bytes "
             << bytes_to_string(
                    following_bytes,
                    min<size_t>(following_bytes_count,
                        sizeof(syscall_patch_hook::patch_region_bytes)));

  return nullptr;
}

// Syscalls can be patched either on entry or exit. For most syscall
// instruction code patterns we can steal bytes after the syscall instruction
// and thus we patch on entry, but some patterns require using bytes from
// before the syscall instruction itself and thus can only be patched on exit.
// The `entering_syscall` flag tells us whether or not we're at syscall entry.
// If we are, and we find a pattern that can only be patched at exit, we'll
// set a flag on the RecordTask telling it to try again after syscall exit.
bool Monkeypatcher::try_patch_syscall_x86ish(RecordTask* t, remote_code_ptr ip, bool entering_syscall,
                                             SupportedArch arch, bool &should_retry) {
  ASSERT(t, is_x86ish(arch)) << "Unsupported architecture";

  size_t instruction_length = rr::syscall_instruction_length(arch);
  bool transient_failure = false;
  const syscall_patch_hook* hook_ptr = find_syscall_hook(t, ip - instruction_length,
      entering_syscall, instruction_length, should_retry, transient_failure);
  bool success = false;
  // `syscallno` isn't necessarily correct here (in the extremely rare corner case that we
  // deferred a patch and the signal handler changed it), but we only use it for logging.
  intptr_t syscallno = t->regs().original_syscallno();
  if (hook_ptr) {
    // Get out of executing the current syscall before we patch it.
    if (entering_syscall && !t->exit_syscall_and_prepare_restart()) {
      return false;
    }

    LOG(debug) << "Patching syscall at " << ip << " syscall "
               << syscall_name(syscallno, t->arch()) << " tid " << t->tid;

    success = patch_syscall_with_hook(*this, t, *hook_ptr, ip - instruction_length, instruction_length, 0);
    if (!success && entering_syscall) {
      // Need to reenter the syscall to undo exit_syscall_and_prepare_restart
      t->enter_syscall();
    }
  }

  if (!success) {
    if (!should_retry && !transient_failure) {
      LOG(debug) << "Failed to patch syscall at " << ip << " syscall "
                 << syscall_name(syscallno, t->arch()) << " tid " << t->tid;
      tried_to_patch_syscall_addresses.insert(ip);
    }
    return false;
  }

  return true;
}

bool Monkeypatcher::try_patch_syscall_aarch64(RecordTask* t, remote_code_ptr ip, bool entering_syscall) {
  uint32_t inst[2] = {0, 0};
  size_t bytes_count = t->read_bytes_fallible(ip.to_data_ptr<uint8_t>() - 8, 8, &inst);
  if (bytes_count < sizeof(inst) || inst[1] != 0xd4000001) {
    LOG(debug) << "Declining to patch syscall at "
               << ip - 4 << " for unexpected instruction";
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }
  // mov x8, 0xdc
  if (inst[0] == 0xd2801b88) {
    // Clone may either cause the new and the old process to share stack (vfork)
    // or replacing the stack (pthread_create)
    // and requires special handling on the caller.
    // Our syscall hook cannot do that so this would have to be a raw syscall.
    // We can handle this at runtime but if we know the call is definitely
    // a clone we can avoid patching it here.
    LOG(debug) << "Declining to patch clone syscall at " << ip - 4;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  ASSERT(t, (syscall_hooks.size() == 1 && syscall_hooks[0].patch_region_length == 4 &&
             memcmp(syscall_hooks[0].patch_region_bytes, &inst[1], 4) == 0))
    << "Unknown syscall hook";

  if (!safe_for_syscall_patching(ip - 4, ip, t)) {
    LOG(debug)
      << "Temporarily declining to patch syscall at " << ip - 4
      << " because a different task has its ip in the patched range";
    return false;
  }

  // Get out of executing the current syscall before we patch it.
  if (entering_syscall && !t->exit_syscall_and_prepare_restart()) {
    return false;
  }

  LOG(debug) << "Patching syscall at " << ip - 4 << " syscall "
             << syscall_name(t->regs().original_syscallno(), aarch64) << " tid " << t->tid;

  auto success = patch_syscall_with_hook(*this, t, syscall_hooks[0], ip - 4, 4, 0);
  if (!success && entering_syscall) {
    // Need to reenter the syscall to undo exit_syscall_and_prepare_restart
    if (!t->enter_syscall()) {
      return false;
    }
  }

  if (!success) {
    LOG(debug) << "Failed to patch syscall at " << ip - 4 << " syscall "
               << syscall_name(t->regs().original_syscallno(), aarch64) << " tid " << t->tid;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  return true;
}


bool Monkeypatcher::try_patch_syscall(RecordTask* t, bool entering_syscall, bool &should_retry) {
  Registers r = t->regs();
  remote_code_ptr ip = r.ip();
  return try_patch_syscall(t, entering_syscall, should_retry, ip);
}

bool Monkeypatcher::try_patch_syscall(RecordTask* t, bool entering_syscall, bool &should_retry, remote_code_ptr ip) {
  if (syscall_hooks.empty()) {
    // Syscall hooks not set up yet. Don't spew warnings, and don't
    // fill tried_to_patch_syscall_addresses with addresses that we might be
    // able to patch later.
    return false;
  }
  if (t->emulated_ptracer) {
    // Syscall patching can confuse ptracers, which may be surprised to see
    // a syscall instruction at the current IP but then when running
    // forwards, that the syscall occurs deep in the preload library instead.
    return false;
  }
  if (t->is_in_traced_syscall()) {
    // Never try to patch the traced-syscall in our preload library!
    return false;
  }

  // We should not get here for untraced syscalls or anything else from the rr page.
  // These should be normally prevented by our seccomp filter
  // and in the case of syscalls interrupted by signals,
  // the check for the syscall restart should prevent us from reaching here.
  ASSERT(t, ip.to_data_ptr<void>() < AddressSpace::rr_page_start() ||
            ip.to_data_ptr<void>() >= AddressSpace::rr_page_end());
  if (tried_to_patch_syscall_addresses.count(ip) || is_jump_stub_instruction(ip, true)) {
    return false;
  }

  // We could examine the current syscall number and if it's not one that
  // we support syscall buffering for, refuse to patch the syscall instruction.
  // This would, on the face of it, reduce overhead since patching the
  // instruction just means a useless trip through the syscall buffering logic.
  // However, it actually wouldn't help much since we'd still do a switch
  // on the syscall number in this function instead, and due to context
  // switching costs any overhead saved would be insignificant.
  // Also, implementing that would require keeping a buffered-syscalls
  // list in sync with the preload code, which is unnecessary complexity.

  SupportedArch arch;
  if (!get_syscall_instruction_arch(
          t, ip.decrement_by_syscall_insn_length(t->arch()), &arch) ||
      arch != t->arch()) {
    LOG(debug) << "Declining to patch cross-architecture syscall at " << ip;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  // Emit FLUSH_SYSCALLBUF if there's one pending.
  // We want our mmap records to be associated with the next (PATCH_SYSCALL)
  // event, not a FLUSH_SYSCALLBUF event.
  t->maybe_flush_syscallbuf();
  if (!t->is_stopped()) {
    // Tracee was unexpectedly kicked out of a ptrace-stop by SIGKILL or
    // equivalent. Abort trying to patch.
    return false;
  }

  if (arch == aarch64) {
    return try_patch_syscall_aarch64(t, ip, entering_syscall);
  }
  return try_patch_syscall_x86ish(t, ip, entering_syscall, arch, should_retry);
}

bool Monkeypatcher::try_patch_trapping_instruction(RecordTask* t, size_t instruction_length,
                                                   bool before_instruction, bool &should_retry) {
  if (syscall_hooks.empty()) {
    // Syscall hooks not set up yet. Don't spew warnings, and don't
    // fill tried_to_patch_syscall_addresses with addresses that we might be
    // able to patch later.
    return false;
  }
  if (t->emulated_ptracer) {
    // Patching can confuse ptracers.
    return false;
  }

  Registers r = t->regs();
  remote_code_ptr ip_of_instruction = r.ip() - (before_instruction ? 0 : instruction_length);
  if (tried_to_patch_syscall_addresses.count(ip_of_instruction + instruction_length)) {
    return false;
  }

  // Emit FLUSH_SYSCALLBUF if there's one pending.
  // We want our mmap records to be associated with the next (PATCH_SYSCALL)
  // event, not a FLUSH_SYSCALLBUF event.
  t->maybe_flush_syscallbuf();

  bool transient_failure = false;
  const syscall_patch_hook* hook_ptr =
    find_syscall_hook(t, ip_of_instruction, before_instruction, instruction_length, should_retry, transient_failure);
  bool success = false;
  if (hook_ptr) {
    LOG(debug) << "Patching trapping instruction at " << ip_of_instruction << " tid " << t->tid;

    success = patch_syscall_with_hook(*this, t, *hook_ptr, ip_of_instruction,
                                      instruction_length, SYS_rrcall_rdtsc);
  }

  if (!success) {
    if (!should_retry && !transient_failure) {
      LOG(debug) << "Failed to patch trapping instruction at " << ip_of_instruction << " tid " << t->tid;
      tried_to_patch_syscall_addresses.insert(ip_of_instruction + instruction_length);
    }
    return false;
  }

  return true;
}

// VDSOs are filled with overhead critical functions related to getting the
// time and current CPU.  We need to ensure that these syscalls get redirected
// into actual trap-into-the-kernel syscalls so rr can intercept them.

template <typename Arch>
static void patch_after_exec_arch(RecordTask* t, Monkeypatcher& patcher);

template <typename Arch>
static void patch_at_preload_init_arch(RecordTask* t, Monkeypatcher& patcher);

template <>
void patch_after_exec_arch<X86Arch>(RecordTask* t, Monkeypatcher& patcher) {
  (void)patcher;
  setup_preload_library_path<X86Arch>(t);
  setup_audit_library_path<X86Arch>(t);

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
    patch_auxv_vdso(t, X86Arch::RR_AT_SYSINFO, librrpage_base +
      AddressSpace::RRVDSO_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE);
  }
}

// Monkeypatch x86 vsyscall hook only after the preload library
// has initialized. The vsyscall hook expects to be able to use the syscallbuf.
// Before the preload library has initialized, the regular vsyscall code
// will trigger ptrace traps and be handled correctly by rr.
template <>
void patch_at_preload_init_arch<X86Arch>(RecordTask* t,
                                         Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X86Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

template <>
void patch_after_exec_arch<X64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X64Arch>(t);
  setup_audit_library_path<X64Arch>(t);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes(), -1,
                             Monkeypatcher::MMAP_EXEC);
    patcher.software_counter_instrument_after_mmap(*t, km.start(), km.size(),
                             km.file_offset_bytes(), -1,
                             Monkeypatcher::MMAP_EXEC);
  }

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
  }
}

template <>
void patch_after_exec_arch<ARM64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<ARM64Arch>(t);
  setup_audit_library_path<ARM64Arch>(t);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes(), -1,
                             Monkeypatcher::MMAP_EXEC);
    patcher.software_counter_instrument_after_mmap(*t, km.start(), km.size(),
                             km.file_offset_bytes(), -1,
                             Monkeypatcher::MMAP_EXEC);
  }

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*PRELOAD_LIBRARY_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
  }
}

template <>
void patch_at_preload_init_arch<X64Arch>(RecordTask* t,
                                         Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X64Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

template <>
void patch_at_preload_init_arch<ARM64Arch>(RecordTask* t,
                                           Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<ARM64Arch>>(t->regs().orig_arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

void Monkeypatcher::patch_after_exec(RecordTask* t) {
  ASSERT(t, 1 == t->vm()->task_set().size())
      << "Can't have multiple threads immediately after exec!";

  RR_ARCH_FUNCTION(patch_after_exec_arch, t->arch(), t, *this);
}

void Monkeypatcher::patch_at_preload_init(RecordTask* t) {
  // NB: the tracee can't be interrupted with a signal while
  // we're processing the rrcall, because it's masked off all
  // signals.
  RR_ARCH_FUNCTION(patch_at_preload_init_arch, t->arch(), t, *this);
}

static remote_ptr<void> resolve_address(ElfReader& reader, uintptr_t elf_addr,
                                        remote_ptr<void> map_start,
                                        size_t map_size,
                                        uintptr_t map_offset) {
  uintptr_t file_offset;
  if (!reader.addr_to_offset(elf_addr, file_offset)) {
    LOG(warn) << "ELF address " << HEX(elf_addr) << " not in file";
  }
  if (file_offset < map_offset || file_offset > map_offset + map_size) {
    // The value(s) to be set are outside the mapped range. This happens
    // because code and data can be mapped in separate, partial mmaps in which
    // case some symbols will be outside the mapped range.
    return nullptr;
  }
  return map_start + uintptr_t(file_offset - map_offset);
}

static remote_ptr<void> set_and_record_bytes(RecordTask* t, ElfReader& reader,
                                 uintptr_t elf_addr, const void* bytes,
                                 size_t size, remote_ptr<void> map_start,
                                 size_t map_size, size_t map_offset) {
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset);
  if (!addr) {
    return remote_ptr<void>();
  }
  bool ok = true;
  t->write_bytes_helper(addr, size, bytes, &ok);
  // Writing can fail when the value appears to be in the mapped range, but it
  // actually is beyond the file length.
  if (ok) {
    t->record_local(addr, size, bytes);
  }
  return addr;
}

/**
 * Patch _dl_runtime_resolve_(fxsave,xsave,xsavec) to clear "FDP Data Pointer"
 * register so that CPU-specific behaviors involving that register don't leak
 * into stack memory.
 */
void Monkeypatcher::patch_dl_runtime_resolve(RecordTask* t, ElfReader& reader,
                                             uintptr_t elf_addr,
                                             remote_ptr<void> map_start,
                                             size_t map_size,
                                             size_t map_offset) {
  if (t->arch() != x86_64) {
    return;
  }
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset);
  if (!addr) {
    return;
  }

  uint8_t impl[X64DLRuntimeResolve::size + X64EndBr::size];
  uint8_t *impl_start = impl;
  t->read_bytes(addr, impl);
  if (X64EndBr::match(impl) || X86EndBr::match(impl)) {
    static_assert(X64EndBr::size == X86EndBr::size, "EndBr patch size mismatch");
    LOG(debug) << "Starts with endbr, skipping";
    addr += X64EndBr::size;
    impl_start += X64EndBr::size;
  }

  static_assert(X64DLRuntimeResolve::size == X64DLRuntimeResolve2::size,
                "DLRuntimeResolve patch size mismatch");
  if (!X64DLRuntimeResolve::match(impl_start) &&
      !X64DLRuntimeResolve2::match(impl_start)) {
    LOG(warn) << "_dl_runtime_resolve implementation doesn't look right";
    return;
  }

  vector<uint8_t> bytes(impl_start, impl_start + X64DLRuntimeResolve::size);
  auto call_patch_start = addr.cast<uint8_t>();
  saved_dl_runtime_resolve_code[call_patch_start] = std::move(bytes);

  uint8_t call_patch[X64AbsoluteIndirectCallMonkeypatch::size];
  X64AbsoluteIndirectCallMonkeypatch::substitute(call_patch,
      RR_DL_RUNTIME_RESOLVE_CLEAR_FIP);
  write_and_record_bytes(t, call_patch_start, call_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  uint8_t nops[X64DLRuntimeResolve::size - sizeof(call_patch)];
  memset(nops, NOP, sizeof(nops));
  write_and_record_mem(t, call_patch_start + sizeof(call_patch), nops,
                       sizeof(nops));
}

void Monkeypatcher::unpatch_dl_runtime_resolves(RecordTask* t) {
  for (auto entry : saved_dl_runtime_resolve_code) {
    remote_ptr<uint8_t> addr = entry.first;
    uint8_t impl[X64DLRuntimeResolve::size];
    bool ok = true;
    t->read_bytes_helper(addr, sizeof(impl), impl, &ok);
    if (!ok) {
      LOG(warn) << "dl_runtime_resolve code has gone!";
      continue;
    }
    uint8_t call_patch[X64AbsoluteIndirectCallMonkeypatch::size];
    X64AbsoluteIndirectCallMonkeypatch::substitute(call_patch,
      RR_PAGE_ADDR - PRELOAD_LIBRARY_PAGE_SIZE);
    if (memcmp(impl, call_patch, sizeof(call_patch))) {
      LOG(warn) << "dl_runtime_resolve code has changed!";
      continue;
    }
    write_and_record_mem(t, addr, entry.second.data(), entry.second.size());
  }
  saved_dl_runtime_resolve_code.clear();
}

// https://documentation-service.arm.com/static/67581b3355451e3c38d97c22
static bool is_aarch64_bti(uint32_t instruction) {
  if ((instruction >> 12) == 0b11010101000000110010 && (instruction & 0x1f) == 0b11111) {
    // Hint instruction.
    uint32_t crm = (instruction >> 8) & ((1 << 4) - 1);
    uint32_t op2 = (instruction >> 5) & ((1 << 3) - 1);
    return crm == 0b0100 && (op2 & 1) == 0;
  }
  return false;
}

static bool is_aarch64_adrp(uint32_t instruction, remote_ptr<void> pc, remote_ptr<void>* address) {
  if ((instruction >> 31) == 1 && ((instruction >> 24) & 0x1f) == 0b10000) {
    uint64_t base = (pc.as_int() >> 12) << 12;
    uint64_t imm =  ((instruction >> 29) & 0x3) +
        (((instruction >> 5) & ((1 << 19) - 1)) << 2);
    *address = remote_ptr<void>(base + (imm << 12));
    return true;
  }
  return false;
}

static bool is_aarch64_ldrb(uint32_t instruction, uint32_t* offset) {
  if ((instruction >> 22) == 0b0011100101) {
    *offset = (instruction >> 10) & ((1 << 12) - 1);
    return true;
  }
  return false;
}

/**
 * Patch the __aarch64_have_lse_atomics variable to ensure that LSE atomics are
 * always used even if init_lse_atomics
 */
void Monkeypatcher::patch_aarch64_have_lse_atomics(RecordTask* t, ElfReader& reader,
                                                   uintptr_t ldadd4_addr,
                                                   remote_ptr<void> map_start,
                                                   size_t map_size,
                                                   size_t map_offset) {
  ASSERT(t, t->arch() == aarch64);
  remote_ptr<void> addr =
    resolve_address(reader, ldadd4_addr, map_start, map_size, map_offset);
  if (!addr) {
    return;
  }

  bool ok = true;
  uint8_t instruction_bytes[12];
  t->read_bytes_helper(addr, sizeof(instruction_bytes), instruction_bytes, &ok);
  if (!ok) {
    LOG(warn) << "Can't read ldadd4 instruction bytes at " << addr;
    return;
  }
  uint32_t instructions[3];
  memcpy(instructions, instruction_bytes, sizeof(instructions));
  int index = 0;
  if (is_aarch64_bti(instructions[0])) {
    ++index;
  }
  remote_ptr<void> adrp_address;
  if (!is_aarch64_adrp(instructions[index], addr + index*4, &adrp_address)) {
    LOG(warn) << "Instruction 0x" << HEX(instructions[index]) << " is not ADRP";
    return;
  }
  uint32_t ldrb_offset;
  if (!is_aarch64_ldrb(instructions[index + 1], &ldrb_offset)) {
    LOG(warn) << "Instruction 0x" << HEX(instructions[index + 1]) << " is not LDRB";
    return;
  }
  remote_ptr<void> have_lse_atomics_addr = adrp_address + ldrb_offset;
  uint8_t enable = 1;
  write_and_record_mem(t, have_lse_atomics_addr.cast<uint8_t>(), &enable, 1);
}

static bool file_may_need_instrumentation(const AddressSpace::Mapping& map) {
  size_t file_part = map.map.fsname().rfind('/');
  if (file_part == string::npos) {
    file_part = 0;
  } else {
    ++file_part;
  }
  const string& fsname = map.map.fsname();
  return fsname.find("libpthread", file_part) != string::npos ||
    fsname.find("ld", file_part) != string::npos;
}

static bool file_may_need_software_counter_instrumentation(
    const AddressSpace::Mapping& map) {
  const string& fsname = map.map.fsname();
  if (fsname.empty() || fsname == "[stack]" || fsname == "[vdso]") {
    LOG(debug) << "Declining to dynamically software counter instrument: `"
               << fsname << "` " << map.map.start() << "-" << map.map.end();
    return false;
  }
  size_t file_part = fsname.rfind('/');
  if (file_part == string::npos) {
    file_part = 0;
  } else {
    ++file_part;
  }
  auto ret = fsname.find("librrpage", file_part) != string::npos ||
             fsname.find(SOFT_COUNT_STUB_TEMP_NAME, file_part) != string::npos;
  if (ret) {
    LOG(debug) << "Declining to dynamically software counter instrument: `"
               << fsname << "` " << map.map.start() << "-" << map.map.end();
    return false;
  }
  return true;
}

// Should the mapping be software counter instrumented in
// Monkeypatcher::software_counter_instrument_after_mmap or gradually via the SIGSEGV approach ?
static bool dynamically_instrument_now(const RecordSession& sess,
                                       const AddressSpace::Mapping& map) {
  const string& fsname = map.map.fsname();
  size_t file_part = fsname.rfind('/');
  if (file_part == string::npos) {
    file_part = 0;
  } else {
    ++file_part;
  }
  // librrpreload.so is internal to rr and a sensitive piece of machinery.
  // Always instrument in one go aka "now", regardless of what strategy the user
  // gave us.
  if (fsname.find("librrpreload.so", file_part) != string::npos) {
    return true;
  } else if (sess.software_counting_strategy() == SCS_ALWAYS_JII) {
    return false;
  } else if (sess.software_counting_strategy() == SCS_NEVER_JII) {
    return true;
  }
  // SCS_BASIC & SCS_MINIMAL
  auto ret = fsname.find("libc.so", file_part) != string::npos ||
             fsname.find("libpthread.so", file_part) != string::npos ||
             fsname.find("libdl.so", file_part) != string::npos ||
             fsname.find("librt.so", file_part) != string::npos ||
             fsname.find("ld-linux-aarch64.so", file_part) != string::npos;
  return ret;
}

static bool part_of_minimal_set(const AddressSpace::Mapping& map) {
  const string& fsname = map.map.fsname();
  size_t file_part = fsname.rfind('/');
  if (file_part == string::npos) {
    file_part = 0;
  } else {
    ++file_part;
  }
  auto ret = fsname.find("librrpreload.so", file_part) != string::npos ||
             fsname.find("libc.so", file_part) != string::npos ||
             fsname.find("libpthread.so", file_part) != string::npos ||
             fsname.find("libdl.so", file_part) != string::npos ||
             fsname.find("librt.so", file_part) != string::npos ||
             fsname.find("ld-linux-aarch64.so", file_part) != string::npos;
  return ret;
}

template <typename Arch>
static void instrument_with_software_counters_arch(
    Monkeypatcher&, RecordTask& t, const remote_ptr<void>,
    const remote_ptr<void>, const KernelMapping&, rocksdb::DB&) {
  ASSERT(&t, false) << "Architecture not supported. enum SupportedArch value: "
                    << t.arch();
  __builtin_unreachable();
}

template <>
void instrument_with_software_counters_arch<ARM64Arch>(
    Monkeypatcher& patcher, RecordTask& t, const remote_ptr<void> addr_start,
    const remote_ptr<void> addr_end, const KernelMapping& map,
    rocksdb::DB& db) {
  ASSERT(&t, map.start() >= addr_start);
  ASSERT(&t, addr_end <= map.end());
  const remote_ptr<uint32_t> instrumentation_addr_start =
      addr_start.cast<uint32_t>();
  const remote_ptr<uint32_t> instrumentation_addr_end =
      addr_end.cast<uint32_t>();

  vector<uint32_t> inst_buff;
  inst_buff.resize(SC_AARCH64_STUB_LEN);
  memcpy(inst_buff.data(), SC_AARCH64_STUB, SC_AARCH64_STUB_SIZE_BYTES);

  const size_t map_file_offset_bytes = map.file_offset_bytes();
  const auto map_start = map.start();
  const size_t min_file_offset = map_file_offset_bytes +
                                 instrumentation_addr_start.as_int() -
                                 map_start.as_int();
  const size_t max_file_offset = map_file_offset_bytes +
                                 instrumentation_addr_end.as_int() -
                                 map_start.as_int();
  ASSERT(&t, min_file_offset < max_file_offset);

  const auto upper_bound = rocksdb::Slice(
      reinterpret_cast<const char*>(&max_file_offset), sizeof(uint64_t));
  const auto lower_bound = rocksdb::Slice(
      reinterpret_cast<const char*>(&min_file_offset), sizeof(uint64_t));
  rocksdb::ReadOptions options;
  options.iterate_upper_bound = &upper_bound;
  auto it = unique_ptr<rocksdb::Iterator>(db.NewIterator(options));
  it->Seek(lower_bound);

  size_t patched = 0;
  while (it->Valid()) {
    const uint64_t file_offset =
        *reinterpret_cast<const uint64_t*>(it->key().data());
    remote_ptr<uint32_t> instrumentation_addr =
        (map_start + file_offset - map_file_offset_bytes).cast<uint32_t>();
    const uint32_t instr = t.read_mem(instrumentation_addr);
    if (is_conditional_branch_aarch64(instr)) {
      const remote_ptr<uint32_t> jump_stub_start =
          allocate_software_counter_stub_aarch64(
              t, patcher.software_counter_stub_areas,
              patcher.last_used_software_counter_stub_area, instr,
              instrumentation_addr, inst_buff);
      if (jump_stub_start) {
        const int64_t jump_delta =
            int64_t(jump_stub_start.as_int() - instrumentation_addr.as_int());
        ASSERT(&t, MIN_AARCH64_JUMP_DELTA <= jump_delta &&
                       jump_delta <= MAX_AARCH64_JUMP_DELTA);
        const uint32_t imm26 = 0x3FF'FFFF & (jump_delta >> 2);
        const uint32_t new_instr = 0x14000000 | imm26;
        write_and_record_mem(&t, instrumentation_addr, &new_instr, 1);
        write_and_record_mem(&t, jump_stub_start, inst_buff.data(),
                             inst_buff.size());
        patched++;
      }
    }
    it->Next();
  }
  LOG(debug) << "Patched: " << patched << " conditional branches in "
             << map.fsname() << " from: " << instrumentation_addr_start
             << " to: " << instrumentation_addr_end;
}

template <>
void instrument_with_software_counters_arch<X64Arch>(
    Monkeypatcher& patcher, RecordTask& t, const remote_ptr<void> addr_start,
    const remote_ptr<void> addr_end, const KernelMapping& map,
    rocksdb::DB& db) {
  vector<uint8_t> stub_buff;
  stub_buff.resize(SC_X64_PRELUDE_SIZE_BYTES);
  memcpy(stub_buff.data(), SC_X64_PRELUDE, SC_X64_PRELUDE_SIZE_BYTES);
  vector<uint8_t> instr_patch;

  ASSERT(&t, map.start() >= addr_start);
  ASSERT(&t, addr_end <= map.end());
  const remote_ptr<uint8_t> instrumentation_addr_start =
      addr_start.cast<uint8_t>();
  const remote_ptr<uint8_t> instrumentation_addr_end = addr_end.cast<uint8_t>();

  const uint64_t map_file_offset_bytes = map.file_offset_bytes();
  const auto map_start = map.start();
  const size_t min_file_offset = map_file_offset_bytes +
                                 instrumentation_addr_start.as_int() -
                                 map_start.as_int();
  const size_t max_file_offset = map_file_offset_bytes +
                                 instrumentation_addr_end.as_int() -
                                 map_start.as_int();
  ASSERT(&t, min_file_offset < max_file_offset);

  const auto upper_bound = rocksdb::Slice(
      reinterpret_cast<const char*>(&max_file_offset), sizeof(uint64_t));
  const auto lower_bound = rocksdb::Slice(
      reinterpret_cast<const char*>(&min_file_offset), sizeof(uint64_t));
  rocksdb::ReadOptions options;
  options.iterate_upper_bound = &upper_bound;
  auto it = unique_ptr<rocksdb::Iterator>(db.NewIterator(options));
  it->Seek(lower_bound);

  size_t num_patched = 0;
  while (it->Valid()) {
    const uint64_t file_offset =
        *reinterpret_cast<const uint64_t*>(it->key().data());
    const PatchData* patch_data =
        reinterpret_cast<const PatchData*>(it->value().data());
    remote_ptr<uint8_t> instrumentation_addr =
        map_start.cast<uint8_t>() + (file_offset - map_file_offset_bytes);
    const vector<uint8_t> insn_bytes =
        t.read_mem(instrumentation_addr, patch_data->len);
    if (memcmp(patch_data->data, insn_bytes.data(), patch_data->len)) {
      it->Next();
      continue;
    }
    const remote_ptr<uint8_t> jump_stub_start =
        allocate_software_counter_stub_x64(
            t, patcher.software_counter_stub_areas,
            patcher.last_used_software_counter_stub_area, instrumentation_addr,
            *patch_data, stub_buff, instr_patch);
    if (!jump_stub_start) {
      it->Next();
      continue;
    }
    ASSERT(&t, instr_patch.size() == insn_bytes.size());
    write_and_record_mem(&t, instrumentation_addr, instr_patch.data(),
                         instr_patch.size());
    write_and_record_mem(&t, jump_stub_start, stub_buff.data(),
                         stub_buff.size());
    num_patched++;
    it->Next();
  }
  LOG(debug) << "Patched: " << num_patched << " conditional branches in "
             << map.fsname() << " from: " << instrumentation_addr_start
             << " to: " << instrumentation_addr_end;
}

void Monkeypatcher::instrument_with_software_counters(
    RecordTask& t, const remote_ptr<void> instrumentation_addr_start,
    const remote_ptr<void> instrumentation_addr_end, const KernelMapping& map,
    rocksdb::DB& db) {
  RR_ARCH_FUNCTION(instrument_with_software_counters_arch, t.arch(), *this, t,
                   instrumentation_addr_start, instrumentation_addr_end, map,
                   db);
}

static ScopedFd get_mapped_file_fd(Task &t, remote_ptr<void> start, size_t size,
                            int child_fd) {
  ScopedFd open_fd;
  if (child_fd >= 0) {
    open_fd = t.open_fd(child_fd, O_RDONLY);
    ASSERT(&t, open_fd.is_open()) << "Failed to open child fd " << child_fd;
  } else {
    char buf[100];
    sprintf(buf, "/proc/%d/map_files/%llx-%llx", t.tid,
            (long long)start.as_int(), (long long)start.as_int() + size);
    // Reading these directly requires CAP_SYS_ADMIN, so open the link target
    // instead.
    char link[PATH_MAX];
    int ret = readlink(buf, link, sizeof(link) - 1);
    if (ret < 0) {
      return open_fd;
    }
    link[ret] = 0;
    LOG(debug) << "Opening file: `" << link << "` corresponding to: `" << buf << "`";
    char link_in_mnt_namespace[PATH_MAX];
    // Need to open the file in its own mnt namespace otherwise the content may not be
    // what is expected. Example: see mount_ns_exec2 test
    ret = snprintf(link_in_mnt_namespace, PATH_MAX, "/proc/%d/root/%s", t.tid, link);
    if (ret < 0) {
      FATAL() << "error in snprintf";
    }
    open_fd = ScopedFd(link_in_mnt_namespace, O_RDONLY);
    if (!open_fd.is_open()) {
      LOG(warn) << "  ... could not open file: `" << link << "`";
      return open_fd;
    }
  }

  return open_fd;
}

void Monkeypatcher::patch_after_mmap(RecordTask* t, remote_ptr<void> start,
                                     size_t size, size_t offset_bytes,
                                     int child_fd, MmapMode mode) {
  const auto& map = t->vm()->mapping_of(start);
  if (!file_may_need_instrumentation(map)) {
    return;
  }
  if (t->arch() == aarch64 && mode != MMAP_EXEC) {
    return;
  }
  ScopedFd open_fd;
  if (child_fd >= 0) {
    open_fd = t->open_fd(child_fd, O_RDONLY);
    ASSERT(t, open_fd.is_open()) << "Failed to open child fd " << child_fd;
  } else {
    char buf[100];
    sprintf(buf, "/proc/%d/map_files/%llx-%llx", t->tid,
            (long long)start.as_int(), (long long)start.as_int() + size);
    // Reading these directly requires CAP_SYS_ADMIN, so open the link target
    // instead.
    char link[PATH_MAX];
    int ret = readlink(buf, link, sizeof(link) - 1);
    if (ret < 0) {
      return;
    }
    link[ret] = 0;
    open_fd = ScopedFd(link, O_RDONLY);
    if (!open_fd.is_open()) {
      return;
    }
  }
  ElfFileReader reader(open_fd, t->arch());
  // Check for symbols first in the library itself, regardless of whether
  // there is a debuglink.  For example, on Fedora 26, the .symtab and
  // .strtab sections are stripped from the debuginfo file for
  // libpthread.so.
  SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
  if (syms.size() == 0) {
    ScopedFd debug_fd = reader.open_debug_file(map.map.fsname());
    if (debug_fd.is_open()) {
      ElfFileReader debug_reader(debug_fd, t->arch());
      syms = debug_reader.read_symbols(".symtab", ".strtab");
    }
  }
  switch (t->arch()) {
    case x86:
    case x86_64:
      for (size_t i = 0; i < syms.size(); ++i) {
        if (syms.is_name(i, "__elision_aconf")) {
          static const int zero = 0;
          // Setting __elision_aconf.retry_try_xbegin to zero means that
          // pthread rwlocks don't try to use elision at all. See ELIDE_LOCK
          // in glibc's elide.h.
          set_and_record_bytes(t, reader, syms.addr(i) + 8, &zero, sizeof(zero),
                               start, size, offset_bytes);
        }
        if (syms.is_name(i, "elision_init")) {
          // Make elision_init return without doing anything. This means
          // the __elision_available and __pthread_force_elision flags will
          // remain zero, disabling elision for mutexes. See glibc's
          // elision-conf.c.
          static const uint8_t ret = 0xC3;
          set_and_record_bytes(t, reader, syms.addr(i), &ret, sizeof(ret), start,
                               size, offset_bytes);
        }
        // The following operations can only be applied once because after the
        // patch is applied the code no longer matches the expected template.
        // For replaying a replay to work, we need to only apply these changes
        // during a real exec, not during the mmap operations performed when rr
        // replays an exec.
        if (mode == MMAP_EXEC &&
            (syms.is_name(i, "_dl_runtime_resolve_fxsave") ||
             syms.is_name(i, "_dl_runtime_resolve_xsave") ||
             syms.is_name(i, "_dl_runtime_resolve_xsavec"))) {
          patch_dl_runtime_resolve(t, reader, syms.addr(i), start, size,
                                   offset_bytes);
        }
      }
      break;
    case aarch64:
      for (size_t i = 0; i < syms.size(); ++i) {
        if (syms.is_name(i, "__aarch64_ldadd4_relax")) {
          patch_aarch64_have_lse_atomics(t, reader, syms.addr(i), start, size,
                                         offset_bytes);
        }
      }
      break;
  }
}

static void setup_range_for_SIGSEGV(RecordTask& t,
                                    const AddressSpace::Mapping& map) {
  auto orig_prot = map.map.prot();
  ASSERT(&t, orig_prot & PROT_EXEC);
  {
    AutoRemoteSyscalls remote(&t);
    int mprotect_syscallno = syscall_number_for_mprotect(t.arch());
    remote.infallible_syscall_if_alive(mprotect_syscallno, map.map.start(),
                                       map.map.size(), orig_prot & ~PROT_EXEC);
  }
  auto& flags = t.vm()->mapping_flags_of(map.map.start());
  flags |= AddressSpace::Mapping::IS_SOFTWARE_COUNTER_OVERLAY_EXEC;
  auto maybe_unique_id = t.vm()->mapping_unique_id_of(map.map.start());
  LOG(debug) << "setup_range_for_SIGSEGV: Adding overlay exec from: "
             << map.map.start() << "-" << map.map.end() << " for `"
             << map.map.fsname() << "` with unique id:`"
             << (maybe_unique_id ? *maybe_unique_id : "-- not found --") << "`";
  auto map_start = map.map.start();
  auto map_size = map.map.size();
  t.vm()->protect(&t, map_start, map_size, orig_prot & ~PROT_EXEC);

  struct mprotect_record rec{ .start = map_start.as_int(),
                              .size = map_size,
                              .prot = orig_prot & ~PROT_EXEC,
                              .overlay_exec = 1 };
  t.ev().Syscall().mprotect_records.push_back(rec);
}

void Monkeypatcher::software_counter_instrument_after_mmap(
    RecordTask& t, const remote_ptr<void> start_region,
    const size_t size_region, const size_t, const int child_fd,
    const MmapMode) {
  if (!t.hpc.is_software_counter()) {
    return;
  }

  auto& map = t.vm()->mapping_of(start_region);
  // dont want to inadvertently change a file on disk when instrumentation
  // is done
  if (map.map.flags() & MAP_SHARED) {
    LOG(debug) << "map `" << map.map.fsname() << "` from: " << map.map.start()
               << "-" << map.map.end() << " is MAP_SHARED, skipping";
    return;
  }

  if (!(map.map.prot() & PROT_EXEC)) {
    LOG(debug) << "map `" << map.map.fsname() << "` from: " << map.map.start()
               << "-" << map.map.end() << " is not PROT_EXEC, skipping";
    return;
  }

  if (!file_may_need_software_counter_instrumentation(map)) {
    return;
  }

  // if the SCS_MINIMAL strategy is active, only a select set of shared
  // libraries will be instrumented. If map.map.fsname() is not part of that,
  // immediately return
  if (t.session().software_counting_strategy() == SCS_MINIMAL &&
      !part_of_minimal_set(map)) {
    return;
  }

  ScopedFd open_fd = get_mapped_file_fd(t, start_region, size_region, child_fd);
  if (!open_fd.is_open()) {
    return;
  }
  bool ok = true;
  ElfFileReader reader(open_fd, t.arch(), &ok);
  if (!ok) {
    return;
  }
  auto unique_id = reader.read_buildid();
  if (unique_id.size()) {
    auto& maybe_unique_id = t.vm()->mapping_unique_id_of(start_region);
    // Assign the unique id, note the type above is an auto&
    maybe_unique_id = unique_id;
  } else {
    // TODO: do a sha256sum in the mount namespace of the the executable ??
    unique_id = sha256sum(map.map.fsname());
    if (!unique_id.size()) {
      return;
    }
    // Add a prefix to disambiguate with normal build-id unique ids
    unique_id = "sha256=" + unique_id;
    auto& maybe_unique_id = t.vm()->mapping_unique_id_of(start_region);
    // Assign the unique id, note the type above is an auto&
    maybe_unique_id = unique_id;
    LOG(warn) << map.map.fsname()
              << " does not have a build_id, using file sha256sum of "
              << unique_id << " as the unique id";
  }

  auto it = t.session().patchdb_map.find(unique_id);
  if (it == t.session().patchdb_map.end()) {
    // Check for symbols first in the library itself, regardless of whether
    // there is a debuglink.  For example, on Fedora 26, the .symtab and
    // .strtab sections are stripped from the debuginfo file for
    // libpthread.so.
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    if (syms.size() == 0) {
      ScopedFd debug_fd = reader.open_debug_file(map.map.fsname());
      if (debug_fd.is_open()) {
        ElfFileReader debug_reader(debug_fd, t.arch());
        syms = debug_reader.read_symbols(".symtab", ".strtab");
      }
    }

    if (syms.size()) {
      LOG(debug) << syms.size()
                 << " symbols available for: " << map.map.fsname();
    } else {
      // Even if syms.size() is 0, might still want instrument without symbols
      // in the future, either on the fly via SIGSEGV or now (FEATURE
      // UNIMPLEMENTED)
      //
      // XXX: This might be only practical on aarch64 as on x64 could be
      // difficult to do disassembly without symbols and the danger of
      // accidently disassembling data embedded in code !?? Then again
      // it's probably not fully safe on aarch64 also ??
      return;
    }
    t.session().get_or_create_db_of_patch_locations(t, map.map.fsname(), reader,
                                                    syms, unique_id);
  }
  it = t.session().patchdb_map.find(unique_id);
  ASSERT(&t, it != t.session().patchdb_map.end());

  RecordSession::cached_data cached_data = {
    *it->second.db, it->second.already_statically_instrumented
  };

  // no point in either deferring instrumentation or doing it now
  // cause it's already done statically !
  if (cached_data.already_statically_instrumented) {
    return;
  }

  if (dynamically_instrument_now(t.session(), map)) {
    // at "one go" or in other words, now !
    instrument_with_software_counters(
        t, start_region, start_region + size_region, map.map, cached_data.db);
  } else {
    LOG(debug) << "Skipping software counter instrumentation of `"
               << map.map.fsname()
               << "`. It will be done \"just in time\" via SIGSEGV approach";
    setup_range_for_SIGSEGV(t, map);
  }
}

} // namespace rr
