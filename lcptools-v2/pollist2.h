/*
 * pollist2.h:
 *
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __POLLIST2_H__
#define __POLLIST2_H__

extern lcp_list_t *read_policy_list_file(const char *file, bool fail_ok,
                                                      bool *no_sigblock_ok);

extern bool verify_tpm20_policy_list(const lcp_policy_list_t2 *pollist, size_t size,
                               bool *no_sigblock, bool size_is_exact);
extern void display_tpm20_policy_list(const char *prefix,
                                const lcp_policy_list_t2 *pollist, bool brief);

extern lcp_policy_list_t2 *create_empty_tpm20_policy_list(void);

extern lcp_policy_list_t2 *add_tpm20_policy_element(lcp_policy_list_t2 *pollist,
                                             const lcp_policy_element_t *elt);
extern bool del_tpm20_policy_element(lcp_policy_list_t2 *pollist, uint32_t type);

extern bool verify_tpm20_pollist_sig(const lcp_policy_list_t2 *pollist);

extern void display_tpm20_signature(const char *prefix, const lcp_signature_t2 *sig,
                              const uint16_t sig_alg, bool brief);
extern lcp_policy_list_t2 *add_tpm20_signature(lcp_policy_list_t2 *pollist,
                                        const lcp_signature_t2 *sig, const uint16_t sig_alg);
extern unsigned char *get_tpm20_sig_block(const lcp_policy_list_t2 *pollist);

extern void calc_tpm20_policy_list_hash(const lcp_policy_list_t2 *pollist,
                                  lcp_hash_t2 *hash, uint16_t hash_alg);

extern bool write_tpm20_policy_list_file(const char *file,
                                   const lcp_policy_list_t2 *pollist);



#endif    /* __POLLIST2_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
