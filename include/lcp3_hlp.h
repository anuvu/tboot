/*
 * Copyright 2014 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TXT_LCP2_HELPER_H__
#define __TXT_LCP2_HELPER_H__

static inline lcp_signature_t *get_tpm12_signature(const lcp_policy_list_t *pollist)
{
    if ( pollist == NULL )
        return NULL;

    if ( pollist->sig_alg != LCP_POLSALG_RSA_PKCS_15 )
        return NULL;

    return (lcp_signature_t *)((const void *)&pollist->policy_elements +
                               pollist->policy_elements_size);
}

static inline size_t get_tpm12_signature_size(const lcp_signature_t *sig)
{
    if ( sig == NULL )
        return 0;

    return offsetof(lcp_signature_t, pubkey_value) + 2*sig->pubkey_size;
}

static inline size_t get_tpm12_policy_list_size(const lcp_policy_list_t *pollist)
{
    size_t size = 0;

    if ( pollist == NULL )
        return 0;

    size = offsetof(lcp_policy_list_t, policy_elements) +
           pollist->policy_elements_size;

    /* add sig size */
    if ( pollist->sig_alg == LCP_POLSALG_RSA_PKCS_15 )
        size += get_tpm12_signature_size(get_tpm12_signature(pollist));

    return size;
}

static inline lcp_signature_t2 *get_tpm20_signature(const lcp_policy_list_t2 *pollist)
{
    if ( pollist == NULL || pollist->sig_alg == TPM_ALG_NULL )
        return NULL;

    return (lcp_signature_t2 *)((const void *)&pollist->policy_elements +
                               pollist->policy_elements_size);
}

static inline size_t get_tpm20_signature_size(const lcp_signature_t2 *sig,
                                              const uint16_t sig_alg)
{
    if ( sig == NULL )
         return 0;

    if ( sig_alg == TPM_ALG_RSASSA)
         return offsetof(lcp_rsa_signature_t, pubkey_value) +
                        2*sig->rsa_signature.pubkey_size;
    else if ( sig_alg == TPM_ALG_ECDSA)
        return offsetof(lcp_ecc_signature_t, qx) +
                        2*sig->ecc_signature.pubkey_size;

    return 0;
}

static inline size_t get_tpm20_policy_list_size(const lcp_policy_list_t2 *pollist)
{
    size_t size = 0;

    if ( pollist == NULL )
        return 0;

    size = offsetof(lcp_policy_list_t2, policy_elements) +
           pollist->policy_elements_size;

    /* add sig size */
    if ( pollist->sig_alg == TPM_ALG_RSASSA ||
         pollist->sig_alg == TPM_ALG_ECDSA ||
         pollist->sig_alg == TPM_ALG_SM2 )
        size += get_tpm20_signature_size(get_tpm20_signature(pollist),
                        pollist->sig_alg);

    return size;
}


#endif    /*  __TXT_LCP3_HELPER_H__ */
