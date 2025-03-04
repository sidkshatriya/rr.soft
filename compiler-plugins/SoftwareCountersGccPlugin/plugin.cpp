// GCC plugin for statically instrumenting code with software counters
// Copyright (C) 2024, 2025 Sidharth Kshatriya
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <format>
#include <string_view>

#include "locations.h"
#include "gcc-plugin.h"
#include "stringpool.h"
#include "tree-core.h"
#include "tree-pass.h"
#include "tree.h"
#include "cgraph.h"
#include "stor-layout.h"
#include "gimple.h"
#include "gimple-iterator.h"
#include "basic-block.h"
#include "coretypes.h"

using namespace std;

#define DO_SOFTWARE_COUNT "__do_software_count"
#define SOFT_CNT_ENABLE "__soft_cnt_enable"

#define X8664_instrumentation_string                                           \
  std::format(                                           \
  ".intel_syntax noprefix\n" \
    /* in gcc default calling convention rax and rdi can be clobbered */ \
    /* hence there is no compiler generated push of rax in gcc */ \
    "4: cmp	dword ptr [%0], 0x0\n" \
    "jle 2f\n" \
    /* in gcc default calling convention rax and rdi can be clobbered */ \
    /* OMIT "push rdi\n" */ \
    "mov rdi, 0xcdef89ab45670123\n" \
    /* __ critical section start __ */ \
    "lock\n" \
    "inc     qword ptr [{}]\n" \
    "mov     r11, qword ptr [{}]\n" \
    "cmp     r11, qword ptr [{}]\n" \
    /* Force a short relative jump */ \
    "jl short 1f\n" \
    "mov     r11d, 0x1\n" \
    "xchg    dword ptr [{}], r11d\n" \
    "int3\n" \
    /* will jump here */ \
    "1:\n" \
    "xor     r11d, r11d\n" \
    "xor     rdi, rdi\n" \
    /* ^ end of critical section */ \
    /* in gcc default calling convention rax and rdi can be clobbered */ \
    /* OMIT "pop rdi\n" */ \
    /* OMIT "pop %0\n" */ \
    "ret\n" \
    "2: cmp dword ptr [%0], 0x80000000\n" \
    "je 3f\n" \
    /* in gcc default calling convention rax can be clobbered */ \
    /* OMIT "pop %0\n" */ \
    "ret\n" \
    "3: push r12\n" \
    "mov r12, %0\n" \
    "push rax\n" \
    "push rdi\n" \
    "push rsi\n" \
    "push rdx\n" \
    "push r10\n" \
    "push r8\n" \
    "push r9\n" \
    /* Need to set all syscall parameters to 0 (except rsi) */ \
    /* otherwise the syscall SYS_rrcall_check_presence returns */ \
    /* -EINVAL. Set syscall arg2 to 1 to check if running under rr */ \
    /* in software counters mode */ \
    "mov rax, 0x3f0\n" \
    "mov rdi, 0\n" \
    "mov rsi, 1\n" \
    "mov rdx, 0\n" \
    "mov r10, 0\n" \
    "mov r8, 0\n" \
    "mov r9, 0\n" \
    /* This syscall is not patchable (as desired) */ \
    /* [Monkeypatcher] Trying to patch bytes 0x48 0x3d 0 0xf0 0xff 0xff 0x77 */ \
    /* 0x5 0xc3 0xf 0x1f 0x40 0 0x48 */ \
    /* ... */ \
    /* [Monkeypatcher] Failed to patch syscall at 0x4012ad syscall */ \
    /* rrcall_check_presence tid 331794 */ \
    "syscall\n" \
    "mov dword ptr [r12], eax\n" \
    "pop r9\n" \
    "pop r8\n" \
    "pop r10\n" \
    "pop rdx\n" \
    "pop rsi\n" \
    "pop rdi\n" \
    "pop rax\n" \
    "pop r12\n" \
    "jmp 4b\n" \
    ".att_syntax prefix\n", RR_X8664_CUSTOM_TICKS_ADDR, \
    RR_X8664_CUSTOM_TICKS_ADDR, \
    RR_X8664_CUSTOM_TICKS_TARGET_ADDR, \
    RR_X8664_CUSTOM_TARGET_REACHED_BREAK_ADDR)

extern gcc::context *g;

int plugin_is_GPL_compatible;

tree soft_cnt_enable_var = NULL_TREE;

tree do_software_count_fn = NULL_TREE;

const pass_data software_counters_pass_data = {
    GIMPLE_PASS,
    "software_counters_pass",
    OPTGROUP_NONE,
    TV_NONE,
    PROP_cfg,
    0,
    0,
    0,
    0,
};

class software_counters_pass : public gimple_opt_pass {
public:
  software_counters_pass(gcc::context *ctxt)
      : gimple_opt_pass(software_counters_pass_data, ctxt) {}

  bool gate(function *fun) final override { return true; }
  unsigned int execute(function *fun) final override;
};

static void insert_module_globals() {
  if (soft_cnt_enable_var) {
    return;
  }
  soft_cnt_enable_var =
      build_decl(UNKNOWN_LOCATION, VAR_DECL, get_identifier(SOFT_CNT_ENABLE),
                 integer_type_node);

  // Available from other translation units
  TREE_PUBLIC(soft_cnt_enable_var) = 1;
  TREE_ADDRESSABLE(soft_cnt_enable_var) = 1;
  // static storage
  TREE_STATIC(soft_cnt_enable_var) = 1;
  // defined here
  DECL_EXTERNAL(soft_cnt_enable_var) = 0;
  DECL_ARTIFICIAL(soft_cnt_enable_var) = 1;
  DECL_VISIBILITY(soft_cnt_enable_var) = VISIBILITY_HIDDEN;
  DECL_VISIBILITY_SPECIFIED(soft_cnt_enable_var) = 1;
  DECL_WEAK(soft_cnt_enable_var) = 1;
  // dont cache the result of this variable access, obtain it everytime
  // However, given that this variable will not really be used by the end
  // user it's not clear what impact this has on the generated assembly
  // and whether this is superfluous
  TREE_THIS_VOLATILE(soft_cnt_enable_var) = 1;
  // Set to int32 min
  DECL_INITIAL(soft_cnt_enable_var) =
      build_int_cst(integer_type_node, 0x8000'0000);
  DECL_CONTEXT(soft_cnt_enable_var) = NULL_TREE;
  layout_decl(soft_cnt_enable_var, 0);
  auto node = varpool_node::get_create(soft_cnt_enable_var);
  node->finalize_decl(soft_cnt_enable_var);
  // This is necessary
  node->force_output = 1;

  // node->debug();
}

static void insert_module_functions() {
  if (do_software_count_fn) {
    return;
  }
  tree void_fn_void_type = build_function_type_array(void_type_node, 0, NULL);
  do_software_count_fn = build_fn_decl(DO_SOFTWARE_COUNT, void_fn_void_type);
  // defined here
  DECL_EXTERNAL(do_software_count_fn) = 0;
  DECL_ARTIFICIAL(do_software_count_fn) = 1;
  TREE_PUBLIC(do_software_count_fn) = 1;
  DECL_VISIBILITY(do_software_count_fn) = VISIBILITY_HIDDEN;
  DECL_VISIBILITY_SPECIFIED(do_software_count_fn) = 1;
  DECL_WEAK(do_software_count_fn) = 1;
  DECL_CONTEXT(do_software_count_fn) = NULL_TREE;
  DECL_UNINLINABLE(do_software_count_fn) = 1;
  TREE_USED(do_software_count_fn) = 1;
  DECL_IGNORED_P(do_software_count_fn) = 1;
  tree result_decl =
      build_decl(UNKNOWN_LOCATION, RESULT_DECL, NULL_TREE, void_type_node);
  DECL_CONTEXT(result_decl) = do_software_count_fn;
  DECL_RESULT(do_software_count_fn) = result_decl;
  // __do_software_count() does not call any other functions
  DECL_ATTRIBUTES(do_software_count_fn) = tree_cons(
      get_identifier("leaf"), NULL_TREE, DECL_ATTRIBUTES(do_software_count_fn));

  // Fill out the instrumentation function
  vec<tree, va_gc> *inputs = NULL;
#ifdef __x86_64__
  // function should not have any prologue or epilogue even in -O0
  // This function attribute is not available in aarch64 gcc as of this
  // comment Also, -fno-omit-frame-pointer has no effect on this (TODO:
  // worth more exploration)
  DECL_ATTRIBUTES(do_software_count_fn) =
      tree_cons(get_identifier("naked"), NULL_TREE,
                DECL_ATTRIBUTES(do_software_count_fn));

  // It's actually not neccessary to force rax here, but done for
  // consistency with clang instrumentation
  vec_safe_push(inputs,
                build_tree_list(
                    build_tree_list(NULL_TREE, build_string(strlen("a"), "a")),
                    build_fold_addr_expr(soft_cnt_enable_var)));
  vec<tree, va_gc> *clobbers = NULL;
  vec_safe_push(clobbers,
                build_tree_list(NULL_TREE, build_string(strlen("cc"), "cc")));
  vec_safe_push(clobbers,
                build_tree_list(NULL_TREE, build_string(strlen("rdi"), "rdi")));
  vec_safe_push(clobbers,
                build_tree_list(NULL_TREE, build_string(strlen("r11"), "r11")));
  vec_safe_push(
      clobbers,
      build_tree_list(NULL_TREE, build_string(strlen("memory"), "memory")));

  auto asm_stmt = gimple_build_asm_vec(X8664_instrumentation_string.c_str(),
                                       inputs, NULL, clobbers, NULL);
#else
#error Platform not supported
#endif

  // Need this -- doesnt seem to get emitted otherwise to the binary
  gimple_asm_set_volatile(asm_stmt, true);
  gimple_seq seq = gimple_seq_alloc_with_stmt(asm_stmt);
  auto ret_stmt = gimple_build_return(NULL_TREE);
  gimple_seq_add_stmt(&seq, ret_stmt);

  push_cfun(DECL_STRUCT_FUNCTION(do_software_count_fn));
  auto empty_fn_bb = init_lowered_empty_function(
      do_software_count_fn, false, profile_count::uninitialized());
  auto gsi = gsi_after_labels(empty_fn_bb);
  gsi_insert_seq_before(&gsi, seq, GSI_NEW_STMT);
  cgraph_node::add_new_function(do_software_count_fn, true);
  auto node = cgraph_node::get_create(do_software_count_fn);
  symtab->call_cgraph_insertion_hooks(node);
  // node->debug();
  pop_cfun();
}

unsigned int software_counters_pass::execute(function *fun) {
  insert_module_globals();
  insert_module_functions();
  auto fun_name = IDENTIFIER_POINTER(DECL_NAME(fun->decl));

  if (!strcmp(fun_name, DO_SOFTWARE_COUNT)) {
    return 0;
  }

  if (string_view(fun_name).find("__no_soft_cnt") != string_view::npos) {
    return 0;
  }

  basic_block bb;
  FOR_EACH_BB_FN(bb, fun) {
    auto gsi = gsi_last_nondebug_bb(bb);
    if (gsi_end_p(gsi) || gimple_code(gsi_stmt(gsi)) != GIMPLE_COND) {
      continue;
    }
    auto g = gimple_build_call(do_software_count_fn, 0);
    gsi_insert_before(&gsi, g, GSI_NEW_STMT);
  }

  return 0;
}

int plugin_init(struct plugin_name_args *this_plugin,
                struct plugin_gcc_version *version) {
  struct register_pass_info inserted_pass;
  const char *plugin_name = this_plugin->base_name;

  inserted_pass.pass = new software_counters_pass(g);

  inserted_pass.reference_pass_name = "ssa";
  inserted_pass.ref_pass_instance_number = 1;
  inserted_pass.pos_op = PASS_POS_INSERT_BEFORE;

  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
                    &inserted_pass);

  return 0;
}
