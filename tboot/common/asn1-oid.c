/*
 * ASN.1 OID definitions
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

#include <types.h>

#include "asn1.h"
#include "asn1-oid.h"

#define OID_LEN_MAX			32

/* oid definitions */

/* NOTE: this is not a complete list, but it has worked in testing */

int32_t oid_pkcs7_signeddata[] =	{ 1,2,840,113549,1,7,2 };

int32_t oid_signtime[] = 		{ 1,2,840,113549,1,9,5 };

int32_t oid_ms_indirobj[] =		{ 1,3,6,1,4,1,311,2,1,4 };
int32_t oid_ms_codesign[] =		{ 1,3,6,1,4,1,311,2,1,21 };
int32_t oid_ms_spcimgdataobj[] =	{ 1,3,6,1,4,1,311,2,1,15 };

int32_t oid_commonname[] =		{ 2,5,4,3 };

int32_t oid_x509v3_subkeyid[] =		{ 2,5,29,14 };
int32_t oid_x509v3_keyuse[] =		{ 2,5,29,15 };
int32_t oid_x509v3_cnstr[] =		{ 2,5,29,19 };
int32_t oid_x509v3_athkeyid[] =		{ 2,5,29,35 };

int32_t oid_email[] = 			{ 1,2,840,113549,1,9,1 };
int32_t oid_msgdigest[] = 		{ 1,2,840,113549,1,9,4 };
int32_t oid_smime_caps[] = 		{ 1,2,840,113549,1,9,15 };

int32_t oid_md5[] =			{ 1,2,840,113549,2,5 };
int32_t oid_sha1[] =			{ 1,3,14,3,2,26 };
int32_t oid_sha256[] = 			{ 2,16,840,1,101,3,4,2,1 };
int32_t oid_sha384[] = 			{ 2,16,840,1,101,3,4,2,2 };
int32_t oid_sha512[] = 			{ 2,16,840,1,101,3,4,2,3 };

int32_t oid_rsaenc[] = 			{ 1,2,840,113549,1,1,1 };
int32_t oid_sha256_rsa[] =		{ 1,2,840,113549,1,1,11 };

/* ??? -> http://oid-info.com/get/1.2.840.113549.1.9.3 */
int32_t oid_pkcs9_type3[] = 		{ 1,2,840,113549,1,9,3 };

/* known oid list */

#define OID_LEN(x)			(sizeof(x)/sizeof(int32_t))
#define OID_DEF(x)			{ #x, oid_ ## x, OID_LEN(oid_ ## x) }
const struct oid_def asn1_oid_list[] =
{
    OID_DEF(pkcs7_signeddata),
    OID_DEF(signtime),
    OID_DEF(ms_indirobj),
    OID_DEF(ms_codesign),
    OID_DEF(ms_spcimgdataobj),
    OID_DEF(commonname),
    OID_DEF(x509v3_subkeyid),
    OID_DEF(x509v3_keyuse),
    OID_DEF(x509v3_cnstr),
    OID_DEF(x509v3_athkeyid),
    OID_DEF(email),
    OID_DEF(msgdigest),
    OID_DEF(smime_caps),
    OID_DEF(md5),
    OID_DEF(sha1),
    OID_DEF(sha256),
    OID_DEF(sha384),
    OID_DEF(sha512),
    OID_DEF(rsaenc),
    OID_DEF(sha256_rsa),
    OID_DEF(pkcs9_type3),
};

const struct oid_def *asn1_oid_lookup_oid(int32_t *oid, uint32_t oid_len)
{
    bool match;
    uint32_t i, j;
    const struct oid_def *def;

    if (!oid || oid_len == 0)
        return NULL;

    /* NOTE: this isn't very elegant, but ok for small oid lists */

    for (i = 0; i < sizeof(asn1_oid_list)/sizeof(struct oid_def); i++)
    {
        def = &asn1_oid_list[i];
        /* same size? */
        if (def->len != oid_len)
            continue;
        /* values match? */
        match = true;
        for (j = 0; match && j < oid_len; j++)
        {
            if (def->oid[j] != oid[j])
                match = false;
        }
        /* if everything matches, this is our oid_def */
        if (match)
            return def;
    }

    return NULL;
}

const struct oid_def *asn1_oid_lookup_asn1(struct asn1_value *asn1_val)
{
    int32_t oid[OID_LEN_MAX];
    uint32_t oid_len = 0;

    if (!asn1_val)
        return NULL;

    /* build the oid */
    do
    {
        oid[oid_len] = asn1_obj(asn1_val, oid_len);
        if (oid[oid_len] == ASN1_EOF)
            break;
    }
    while (++oid_len < OID_LEN_MAX);

    /* return the definition */
    return asn1_oid_lookup_oid(oid, oid_len);
}
