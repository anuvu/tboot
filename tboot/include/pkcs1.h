/*
 * PKCS #1 functions
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

#ifndef __PKCS1_H
#define __PKCS1_H

#include "asn1.h"
#include "error.h"

#define PKCS1_OK                ERROR_OK
#define PKCS1_ERR               ERROR_ERR
#define PKCS1_CRYPTERR          ERROR_CRYPTERR
#define PKCS1_CRYPTFAIL         ERROR_CRYPTFAIL

#define CERT_F_NONE             0x00000000
#define CERT_F_TRUSTED          0x00000001
#define CERT_F_TRUSTCHAIN       0x00000002
#define CERT_F_VERIFIED         0x00000010

#define CERT_F_TEST(x,flags)        (((x) & (flags)) == (flags))
#define CERT_F_TESTANY(x,flags)     ((x) & (flags))

struct pkcs1_cert_def
{
    /* major components */
    struct asn1_blob raw;
    struct asn1_blob cert;
    struct asn1_blob signature;

    /* certificate metadata */
    struct asn1_blob version;
    struct asn1_blob serial;
    struct asn1_blob issuer;
    struct asn1_blob issuer_cn;
    struct asn1_blob subject;
    struct asn1_blob subject_cn;
    struct asn1_blob key;
    const char *signature_alg;

    /* pointer to the issuer cert */
    struct pkcs1_cert_def *issuer_cert;
};

int pkcs1_count(void);
void pkcs1_foreachcert(uint32_t flags,
                       int (*callback)(struct pkcs1_cert_def *cert));

int pkcs1_import(unsigned char *blob, uint32_t blob_len, uint32_t flags);

struct pkcs1_cert_def *pkcs1_search_pkcs7signer(struct asn1_blob *subject,
                                                struct asn1_blob *serial);
struct pkcs1_cert_def *pkcs1_search_trustroot(struct pkcs1_cert_def *cert);

#endif
