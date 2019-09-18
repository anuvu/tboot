/*
 * Simplistic stdlib.h functions
 *
 * Copyright (c) 2020 Cisco Systems, Inc. <pmoore2@cisco.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <printk.h>
#include <stdlib.h>

static unsigned long rand_seed = 1;

int tb_rand(void)
{
    /* NOTE: implementation taken from POSIX.1-2001 and assumes RAND_MAX
     *       is set to 32768 (2**15) */
    rand_seed = rand_seed * 1103515245 + 12345;
    return ((unsigned)(rand_seed / 65536) % 32768);
}

void tb_srand(unsigned int seed)
{
    rand_seed = seed;
}

void tb_abort(void)
{
    /* NOTE: this is harsh, but i'm not sure how to emulate this safely */
    printk(TBOOT_ERR"Error: tb_abort() called, attempting to crash\n");
    *(char *)0 = 1;
}
