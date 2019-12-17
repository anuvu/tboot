/*
 * PKCS #7 functions
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

#ifndef __PKCS7_H
#define __PKCS7_H

#include <types.h>

#include "asn1.h"
#include "error.h"

#define PKCS7_OK                ERROR_OK
#define PKCS7_ERR               ERROR_ERR
#define PKCS7_CRYPTERR          ERROR_CRYPTERR
#define PKCS7_CRYPTFAIL         ERROR_CRYPTFAIL

enum pkcs7_verify
{
    PKCS7_V_UNKNOWN = 0,
    PKCS7_V_PASS,
    PKCS7_V_FAIL,
};

struct pkcs7_digest
{
    enum pkcs7_verify verified;
    const char *hash_name;
    struct asn1_blob digest;
};

struct pkcs7_signature
{
    enum pkcs7_verify verified;
    const char *hash_name;
    const char *enc_name;
    struct asn1_blob authattr;
    struct asn1_blob signer;
    struct asn1_blob signer_cn;
    struct asn1_blob signer_serial;
    struct asn1_blob signature;
};

struct pkcs7_mscodesign
{
    enum pkcs7_verify verified;
    const char *hash_name;
    struct asn1_blob digest;
    struct asn1_blob blob;
};

struct pkcs7_signeddata
{
    struct pkcs7_digest digest;
    struct pkcs7_mscodesign contentinfo;
    struct pkcs7_signature signature;
};

int pkcs7_signeddata_parse(struct pkcs7_signeddata *pkcs7,
                           unsigned char *blob, uint32_t blob_len);

int pkcs7_signeddata_sig_verify(struct pkcs7_signeddata *pkcs7,
                                const unsigned char *key_blob,
                                uint32_t key_len);
int pkcs7_signeddata_content_verify(struct pkcs7_signeddata *pkcs7);

#endif
