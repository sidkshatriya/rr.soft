#ifndef locations_h_INCLUDED
#define locations_h_INCLUDED

#include <stddef.h>

#define RR_IMPLEMENT_PRELOAD
#include "preload_interface.h"

#define RR_X8664_PRELOAD_LOCALS_START 0x70001000
#define RR_X8664_CUSTOM_TICKS_ADDR (RR_PRELOAD_LOCALS_START + 144)
#define RR_X8664_CUSTOM_TICKS_TARGET_ADDR (RR_PRELOAD_LOCALS_START + 152)
#define RR_X8664_CUSTOM_ACCUM_TICKS_ADDR (RR_PRELOAD_LOCALS_START + 160)
#define RR_X8664_CUSTOM_TARGET_REACHED_BREAK_ADDR                              \
  (RR_PRELOAD_LOCALS_START + 168)
#define RR_X8664_CUSTOM_CNT_IN_CRITICAL_SECTION_ADDR                           \
  (RR_PRELOAD_LOCALS_START + 172)
#define RR_X8664_CUSTOM_TRACE_TIME_ADDR (RR_PRELOAD_LOCALS_START + 176)
#define RR_X8664_CUSTOM_REC_TID_ADDR (RR_PRELOAD_LOCALS_START + 184)

#ifdef __x86_64__

#define RR_PRELOAD_LOCALS_START RR_X8664_PRELOAD_LOCALS_START
#define RR_CUSTOM_TICKS_ADDR RR_X8664_CUSTOM_TICKS_ADDR
#define RR_CUSTOM_TICKS_TARGET_ADDR RR_X8664_CUSTOM_TICKS_TARGET_ADDR
#define RR_CUSTOM_ACCUM_TICKS_ADDR RR_X8664_CUSTOM_ACCUM_TICKS_ADDR
#define RR_CUSTOM_TARGET_REACHED_BREAK_ADDR                                    \
  RR_X8664_CUSTOM_TARGET_REACHED_BREAK_ADDR
#define RR_CUSTOM_CNT_IN_CRITICAL_SECTION_ADDR                                 \
  RR_X8664_CUSTOM_CNT_IN_CRITICAL_SECTION_ADDR
#define RR_CUSTOM_TRACE_TIME_ADDR RR_X8664_CUSTOM_TRACE_TIME_ADDR
#define RR_CUSTOM_REC_TID_ADDR RR_X8664_CUSTOM_REC_TID_ADDR

#else
_Static_assert(0, "Unsupported Architecture")
#endif

_Static_assert(RR_CUSTOM_TICKS_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals, current_ticks),
               "preload locals offsets wrong");
_Static_assert(RR_CUSTOM_ACCUM_TICKS_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals, accum_ticks),
               "preload locals offsets wrong");
_Static_assert(RR_CUSTOM_TICKS_TARGET_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals, ticks_target),
               "preload locals offsets wrong");
_Static_assert(RR_CUSTOM_TARGET_REACHED_BREAK_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals,
                                ticks_target_was_reached_break),
               "preload locals offsets wrong");
_Static_assert(RR_CUSTOM_CNT_IN_CRITICAL_SECTION_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals,
                                in_critical_section),
               "preload locals offsets wrong");
_Static_assert(RR_CUSTOM_TRACE_TIME_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals, trace_time),
               "preload locals offsets wrong");
_Static_assert(RR_CUSTOM_REC_TID_ADDR ==
                   PRELOAD_THREAD_LOCALS_ADDR +
                       offsetof(struct preload_thread_locals, rec_tid),
               "preload locals offsets wrong");

#endif // locations_h_INCLUDED
