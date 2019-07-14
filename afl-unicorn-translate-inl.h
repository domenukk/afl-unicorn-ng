/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "../../config.h"
#include "tcg-op.h"

/* Declared in afl-qemu-cpu-inl.h */
extern unsigned char *afl_area_ptr;
extern unsigned int afl_inst_rms;

/* Generates TCG code for AFL's tracing instrumentation. */
static void afl_gen_trace(TCGContext *s, target_ulong cur_loc)
{
  static __thread target_ulong prev_loc;
  TCGv index, count, new_prev_loc;
  TCGv_ptr prev_loc_ptr, count_ptr;

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  /* index = prev_loc ^ cur_loc */
  prev_loc_ptr = tcg_const_ptr(s, &prev_loc);
  index = tcg_temp_new(s);
  tcg_gen_ld_tl(s, index, prev_loc_ptr, 0);
  tcg_gen_xori_tl(s, index, index, cur_loc);

  /* afl_area_ptr[index]++ */
  count_ptr = tcg_const_ptr(s, afl_area_ptr);
  tcg_gen_add_ptr(s, count_ptr, count_ptr, TCGV_NAT_TO_PTR(index));
  count = tcg_temp_new(s);
  tcg_gen_ld8u_tl(s, count, count_ptr, 0);
  tcg_gen_addi_tl(s, count, count, 1);
  tcg_gen_st8_tl(s, count, count_ptr, 0);

  /* prev_loc = cur_loc >> 1 */
  new_prev_loc = tcg_const_tl(s, cur_loc >> 1);
  tcg_gen_st_tl(s, new_prev_loc, prev_loc_ptr, 0);
}
