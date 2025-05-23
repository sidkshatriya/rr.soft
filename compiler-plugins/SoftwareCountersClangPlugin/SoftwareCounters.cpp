// Clang plugin for statically instrumenting code with software counters
// Copyright (c) 2023, 2024, 2025 Sidharth Kshatriya
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <llvm/Pass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <stdlib.h>

#include "locations.h"

using namespace llvm;

namespace {

auto AddrTicksHI_aarch64 = itostr(RR_AARCH64_CUSTOM_TICKS_ADDR >> 16);
auto AddrTicksLO_aarch64 = itostr(RR_AARCH64_CUSTOM_TICKS_ADDR & 0xFFFF);

auto AddrTicksReachedBreakHI_aarch64 =
    itostr(RR_AARCH64_CUSTOM_TARGET_REACHED_BREAK_ADDR >> 16);
auto AddrTicksReachedBreakLO_aarch64 =
    itostr(RR_AARCH64_CUSTOM_TARGET_REACHED_BREAK_ADDR & 0xFFFF);

#define SOFT_COUNTER_ENABLE_NAME "__soft_cnt_enable"

#define SOFT_COUNTER_NOTE_SECTION_VAR_NAME "__rr_soft_note"

void InsertSoftCounterEnableGlobal(LLVMContext &C, Module &M) {
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  ConstantInt *MinInt32 = ConstantInt::get(Int32Ty, 0x8000'0000);

  M.getOrInsertGlobal(SOFT_COUNTER_ENABLE_NAME, Int32Ty);
  GlobalVariable *SoftCounterEnable =
      M.getNamedGlobal(SOFT_COUNTER_ENABLE_NAME);
  SoftCounterEnable->setLinkage(GlobalValue::LinkOnceODRLinkage);
  SoftCounterEnable->setVisibility(GlobalValue::HiddenVisibility);
  SoftCounterEnable->setInitializer(MinInt32);
}

void InsertSoftNoteGlobalVar(LLVMContext &C, Module &M) {
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  M.getOrInsertGlobal(SOFT_COUNTER_NOTE_SECTION_VAR_NAME, Int32Ty);
  GlobalVariable *SectionVar =
      M.getNamedGlobal(SOFT_COUNTER_NOTE_SECTION_VAR_NAME);
  SectionVar->setAlignment(Align(4));
  SectionVar->setConstant(true);
  SectionVar->setSection(".rr.soft.instrumented");
  SectionVar->setVisibility(GlobalValue::HiddenVisibility);
  auto comdat = M.getOrInsertComdat("__rr_soft_note");
  comdat->setSelectionKind(Comdat::SelectionKind::Any);
  SectionVar->setComdat(comdat);
  SectionVar->setInitializer(ConstantInt::get(Int32Ty, 1));
  appendToUsed(M, SectionVar);
}

void InsertCounterFunctionWithDefinitionAArch64(LLVMContext &C, Module &M,
                                                FunctionCallee &FC) {
  auto VoidTy = Type::getVoidTy(C);

  auto SoftCounterEnable = M.getNamedGlobal(SOFT_COUNTER_ENABLE_NAME);
  assert(SoftCounterEnable);
  SoftCounterEnable->setVisibility(GlobalValue::HiddenVisibility);

  ///////////////////
  // Create the function itself
  Function *DoSoftwareCountFunc = dyn_cast<Function>(FC.getCallee());
  DoSoftwareCountFunc->setLinkage(GlobalValue::LinkOnceODRLinkage);
  DoSoftwareCountFunc->setVisibility(GlobalValue::HiddenVisibility);
  DoSoftwareCountFunc->setCallingConv(CallingConv::PreserveAll);
  DoSoftwareCountFunc->addFnAttr(Attribute::NoInline);
  DoSoftwareCountFunc->setDoesNotThrow();

  BasicBlock *BB =
      BasicBlock::Create(C, "enter __do_software_count", DoSoftwareCountFunc);
  IRBuilder<> IRB{BB};
  //////////////////////
  // __soft_cnt_enable == 0x8000'0000 (int32 min) means that the variable has not been
  // initialized
  // __soft_cnt_enable == 0 means that software counting is disabled (hardware
  // counters enabled) (program running under rr)
  // __soft_cnt_enable < 0 means that software counting is disabled (program NOT
  // running under rr)
  // (Even though Int32 min is negative, the value of __soft_cnt_enable is set through
  //  syscalls. Negative return values never reach as low as Int32 min)
  // __soft_cnt_enable > 0 means that software counting is enabled (program
  // running under rr)

  auto FuncTypeM =
      FunctionType::get(VoidTy, {SoftCounterEnable->getType()}, false);
  auto asmString =
      "2: ldr w17, [$0]\n"
      "cmp w17, #0x1\n"
      "b.lt 4f\n"
      // Note: Ensure that w8 always remains 1 though this inline asm
      "mov	w8, #0x1\n"
      "mov	w17, #" +
      AddrTicksLO_aarch64 +
      "\n"
      "movk	w17, #" +
      AddrTicksHI_aarch64 +
      ", lsl #16\n"
      "mov	x1, #0x0123\n"
      "movk	x1, #0x4567, lsl #16\n"
      "movk	x1, #0x89AB, lsl #32\n"
      "movk	x1, #0xCDEF, lsl #48\n"
      // with x1 now fully loaded with some sentinel value as of above
      // instruction, the critical section has begun
      "ldadd	x8, x16, [x17]\n"
      // Here the important assumption is that
      // ticks target is stored just after ticks
      "ldp	x16, x17, [x17]\n"
      "cmp	x16, x17\n"
      "b.lt	3f\n"
      "mov	w16, #" +
      AddrTicksReachedBreakLO_aarch64 +
      "\n"
      "movk	w16, #" +
      AddrTicksReachedBreakHI_aarch64 +
      ", lsl #16\n"
      // *AddrTicksReachBreak = 1
      "swp	w8, wzr, [x16]\n"
      // Trap to the ptracer
      "brk	#0\n"
      "3: mov	w16, #0x0\n"
      "mov	w17, #0x0\n"
      "msr	nzcv, xzr\n"
      // Critical section ends after mov completes
      "mov	x1, xzr\n"
      "ret\n"
      "4:\n"
      "mov w8, 0x80000000\n"
      "cmp w8, w17\n"
      "b.eq 5f\n"
      "ret\n"
      "5: mov w8, #0x3f0\n"
      "mov x0, 0\n"
      // Need to set all syscall parameters to 0 (except x1) otherwise the
      // syscall SYS_rrcall_check_presence returns -EINVAL. Set syscall arg2 to 1
      // to check if running under rr in software counters mode
      "mov x1, 1\n"
      "mov x2, 0\n"
      "mov x3, 0\n"
      "mov x4, 0\n"
      "mov x5, 0\n"
      // Doing `b 1f; mov x8, 0xdc` makes this an unpatcheable
      // syscall. See Monkeypatcher::try_patch_syscall_aarch64().
      // Do this to decrease interference while recording.
      // These two instructions otherwise don't change the
      // meaning of the program
      "b 1f\n"
      "mov x8, 0xdc\n"
      "1: svc #0x0\n"
      "str w0, [$0]\n"
      "b 2b\n";
  // x0 - x5, x8, x16, x17 were clobbered
  // Also x7 is not reliably preserved across syscalls
  auto constraintsString = "r,~{x8},~{x0},~{x1},~{x2},~{x3},~{x4},~{x5},~{x7}"
                           ",~{x16},~{x17},~{nzcv},~{memory}";
  auto err = InlineAsm::verify(FuncTypeM, constraintsString);
  assert(!bool(err));

  auto FuncAsmM =
      InlineAsm::get(FuncTypeM, asmString, constraintsString, false);

  IRB.CreateCall(FuncAsmM, {SoftCounterEnable});
  IRB.CreateUnreachable();
}

auto AddrTicksX8664 = itostr(RR_X8664_CUSTOM_TICKS_ADDR);
auto AddrTicksTargetX8664 = itostr(RR_X8664_CUSTOM_TICKS_TARGET_ADDR);
auto AddrTicksReachedBreakX8664 =
    itostr(RR_X8664_CUSTOM_TARGET_REACHED_BREAK_ADDR);

void InsertCounterFunctionWithDefinitionX86_64(LLVMContext &C, Module &M,
                                               FunctionCallee &FC) {
  auto VoidTy = Type::getVoidTy(C);

  auto SoftCounterEnable = M.getNamedGlobal(SOFT_COUNTER_ENABLE_NAME);
  assert(SoftCounterEnable);
  SoftCounterEnable->setVisibility(GlobalValue::HiddenVisibility);

  ///////////////////
  // Create the function itself
  Function *DoSoftwareCountFunc = dyn_cast<Function>(FC.getCallee());
  DoSoftwareCountFunc->setLinkage(GlobalValue::LinkOnceODRLinkage);
  DoSoftwareCountFunc->setVisibility(GlobalValue::HiddenVisibility);
  DoSoftwareCountFunc->setCallingConv(CallingConv::PreserveAll);
  DoSoftwareCountFunc->addFnAttr(Attribute::NoInline);
  DoSoftwareCountFunc->setDoesNotThrow();

  BasicBlock *BB =
      BasicBlock::Create(C, "enter __do_software_count", DoSoftwareCountFunc);
  IRBuilder<> IRB{BB};
  //////////////////////
  // __soft_cnt_enable == 0x8000'0000 (int32 min) means that the variable has not been
  // initialized
  // __soft_cnt_enable == 0 means that software counting is disabled (hardware
  // counters enabled) (program running under rr)
  // __soft_cnt_enable < 0 means that software counting is disabled (program NOT
  // running under rr)
  // (Even though int32 min is negative, the value of __soft_cnt_enable is set through
  //  syscalls. Negative return values never reach as low as Int32 min)
  // __soft_cnt_enable > 0 means that software counting is enabled (program
  // running under rr)

  auto FuncTypeM =
      FunctionType::get(VoidTy, {SoftCounterEnable->getType()}, false);
  auto asmString = "4: cmp	dword ptr [$0], 0x0\n"
                   "jle 2f\n"
                   "push rdi\n"
                   "mov rdi, 0xcdef89ab45670123\n"
                   // __ critical section start __
                   "lock\n"
                   "inc     qword ptr [" +
                   AddrTicksX8664 +
                   "]\n"
                   "mov     r11, qword ptr [" +
                   AddrTicksX8664 +
                   "]\n"
                   "cmp     r11, qword ptr [" +
                   AddrTicksTargetX8664 +
                   "]\n"
                   // Force a short relative jump
                   "jl short 1f\n"
                   "mov     r11d, 0x1\n"
                   "xchg    dword ptr [" +
                   AddrTicksReachedBreakX8664 +
                   "], r11d\n"
                   "int3\n"
                   // will jump here
                   "1:\n"
                   "xor     r11d, r11d\n"
                   "xor     rdi, rdi\n"
                   // ^ end of critical section
                   "pop rdi\n"
                   "pop $0\n"
                   "ret\n"
                   "2: cmp dword ptr [$0], 0x80000000\n"
                   "je 3f\n"
                   "pop $0\n"
                   "ret\n"
                   "3: push r12\n"
                   "mov r12, $0\n"
                   "push rax\n"
                   "push rdi\n"
                   "push rsi\n"
                   "push rdx\n"
                   "push r10\n"
                   "push r8\n"
                   "push r9\n"
                   // Need to set all syscall parameters to 0 (except rsi)
                   // otherwise the syscall SYS_rrcall_check_presence returns
                   // -EINVAL. Set syscall arg2 to 1 to check if running under rr
                   // in software counters mode
                   "mov rax, 0x3f0\n"
                   "mov rdi, 0\n"
                   "mov rsi, 1\n"
                   "mov rdx, 0\n"
                   "mov r10, 0\n"
                   "mov r8, 0\n"
                   "mov r9, 0\n"
                   // This syscall is not patchable (as desired)
                   // [Monkeypatcher] Trying to patch bytes 0x48 0x3d 0 0xf0 0xff 0xff 0x77 0x5 0xc3 0xf 0x1f 0x40 0 0x48
                   // ...
                   // [Monkeypatcher] Failed to patch syscall at 0x4012ad syscall rrcall_check_presence tid 331794
                   "syscall\n"
                   "mov dword ptr [r12], eax\n"
                   "pop r9\n"
                   "pop r8\n"
                   "pop r10\n"
                   "pop rdx\n"
                   "pop rsi\n"
                   "pop rdi\n"
                   "pop rax\n"
                   "pop r12\n"
                   "jmp 4b\n";
  auto constraintsString = "{rax},~{r11},~{cc},~{memory}";
  auto err = InlineAsm::verify(FuncTypeM, constraintsString);
  assert(!bool(err));

  auto FuncAsmM = InlineAsm::get(FuncTypeM, asmString, constraintsString, false,
                                 false, InlineAsm::AD_Intel);

  IRB.CreateCall(FuncAsmM, {SoftCounterEnable});
  IRB.CreateUnreachable();
}

struct SoftwareCounters : PassInfoMixin<SoftwareCounters> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &_MAM) {
    Triple TargetTriple = Triple(M.getTargetTriple());
    bool is_aarch64 = (TargetTriple.getArch() == Triple::aarch64);
    LLVMContext &C = M.getContext();
    auto VerboseModeEnv = getenv("SOFTWARE_COUNTERS_PASS_VERBOSE");
    bool IsVerbose = true;
    if (VerboseModeEnv == nullptr || !strcmp(VerboseModeEnv, "0") ||
        !strcmp(VerboseModeEnv, "")) {
      IsVerbose = false;
    }

    auto SkipEnv = getenv("SOFTWARE_COUNTERS_PASS_SKIP");
    if (SkipEnv && strcmp(SkipEnv, "0") && strcmp(SkipEnv, "")) {
      if (IsVerbose) {
        outs() << "(software-counters) Skipping `" << M.getName()
               << "` due to environment variable SOFTWARE_COUNTERS_PASS_SKIP being truthy\n";
      }

      return PreservedAnalyses::all();
    }

    auto VoidTy = Type::getVoidTy(C);

    auto DoSoftwareCountFuncType = FunctionType::get(VoidTy, {}, false);
    auto DoSoftwareCountCallee =
        M.getOrInsertFunction("__do_software_count", DoSoftwareCountFuncType);

    for (auto &F : M) {
      if (F.isDeclaration()) {
        continue;
      }

      if (F.getName() == "__do_software_count") {
        if (IsVerbose)
          outs() << "(software-counters) Looks like `" << M.getName()
                 << "` has already been instrumented; exiting pass\n";

        return PreservedAnalyses::all();
      }
    }

    if (IsVerbose)
      outs() << "(software-counters) Instrumenting: `" << M.getName() << "`\n";

    bool InstrumentedAFunction = false;
    for (auto &F : M) {
      if (F.isDeclaration()) {
        continue;
      }

      // Quick and dirty way to avoid software counter instrumentation for a
      // function. Probably need to find a better way that avoids changing the
      // function name
      if (F.getName().find("__no_soft_cnt") != StringLiteral::npos) {
        continue;
      }

      std::set<BasicBlock *> toVisit{};
      Triple TargetTriple = Triple(M.getTargetTriple());
      for (auto &BB : F) {
        toVisit.insert(&BB);
      }

      if (IsVerbose)
        outs() << "(software-counters)   Instrumenting Function: `"
               << F.getName() << "`\n";

      for (auto pBB : toVisit) {
        auto *BR = dyn_cast<BranchInst>(pBB->getTerminator());
        if (BR and BR->isConditional()) {
          IRBuilder<> IRB{&*BR};
          IRB.CreateCall(DoSoftwareCountCallee, {});
          InstrumentedAFunction = true;
        }
      }
    }

    // Even if no function ends up getting instrumented in the module, the code should
    // not be considered for dynamic instrumentation anymore -- indicate this by adding
    // a .note.rr.soft ELF section
    InsertSoftNoteGlobalVar(C, M);
    if (InstrumentedAFunction) {
      InsertSoftCounterEnableGlobal(C, M);
      // Now insert the software counter function definition that does the
      // counting
      if (is_aarch64) {
        InsertCounterFunctionWithDefinitionAArch64(C, M, DoSoftwareCountCallee);
      } else {
        InsertCounterFunctionWithDefinitionX86_64(C, M, DoSoftwareCountCallee);
      }
    }
    return PreservedAnalyses::none();
  }
};
} // namespace

llvm::PassPluginLibraryInfo getSoftwareCountersPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "SoftwareCounters", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
          PB.registerOptimizerLastEPCallback(
#if LLVM_VERSION_MAJOR > 19
              [](ModulePassManager &MPM, OptimizationLevel _OM, ThinOrFullLTOPhase _P) {
#else
              [](ModulePassManager &MPM, OptimizationLevel _OM) {
#endif
                MPM.addPass(SoftwareCounters());
              });

          PB.registerPipelineParsingCallback(
              [](StringRef Name, ModulePassManager &MPM,
                 ArrayRef<llvm::PassBuilder::PipelineElement> _C) {
                if (Name == "software-counters") {
                  MPM.addPass(SoftwareCounters());
                  return true;
                } else {
                  return false;
                }
              });
        }
  };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getSoftwareCountersPluginInfo();
}
