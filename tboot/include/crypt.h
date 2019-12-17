/*
 * crypto functions
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

#ifndef __CRYPT_H
#define __CRYPT_H

#include <types.h>
#include <tomcrypt.h>

#include "error.h"

#define CRYPT_OK            ERROR_OK
#define CRYPT_ERR           ERROR_CRYPTERR
#define CRYPT_EINVAL        ERROR_EINVAL
#define CRYPT_FAIL          ERROR_CRYPTFAIL

/*
 * misc
 */

int crypt_init(void);

/*
 * hashing
 */

enum crypt_hash_tokens
{
    CRYPT_HASH_NULL = 0,
    CRYPT_HASH_MD5,
    CRYPT_HASH_SHA1,
    CRYPT_HASH_SHA256,
    CRYPT_HASH_SHA384,
    CRYPT_HASH_SHA512,
};

#define CRYPT_HASH_LEN_MAX  64

struct crypt_hash_def
{
    const char *name;
    const enum crypt_hash_tokens token;
    const uint32_t len;
};

struct crypt_hash_state
{
    const struct crypt_hash_def *def;
    /* libtomcrypt state */
    hash_state state;
};

const struct crypt_hash_def *hash_lookup(const char *name);
uint32_t hash_len_name(const char *name);

int hash_init(struct crypt_hash_state *state, const char *name);
int hash_data(struct crypt_hash_state *state, void *blob, uint32_t blob_len);
int hash_done(struct crypt_hash_state *state, void *blob, uint32_t blob_len);

/*
 * pk
 */

const struct crypt_hash_def *pk_alg_hash(const char *pk_alg);

int pk_verify_pkcs1_v15(const char *digest_name,
                        const unsigned char *digest_blob, uint32_t digest_len,
                        const unsigned char *sig_blob, uint32_t sig_len,
                        const unsigned char *key_blob, uint32_t key_len);

#endif
