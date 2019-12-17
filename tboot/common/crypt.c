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

#include <string.h>
#include <tomcrypt.h>

#include "crypt.h"

/* hash definitions */
const struct crypt_hash_def hash_list[] =
{
    { "md5", CRYPT_HASH_MD5, 16 },
    { "sha1", CRYPT_HASH_SHA1, 20  },
    { "sha256", CRYPT_HASH_SHA256, 32 },
    { "sha384", CRYPT_HASH_SHA384, 48 },
    { "sha512", CRYPT_HASH_SHA512, 64 },
};

/*
 * misc
 */

int crypt_init(void)
{
    /* NOTE: configure tomcrypt to use libtomfastmath */
    ltc_mp = tfm_desc;

    /* TODO: do we want to run the library's hash test functions? */

    /* register the hashes we want to use (see hash_list[]) */
    if (register_hash(&md5_desc) < 0)
        return CRYPT_ERR;
    if (register_hash(&sha1_desc) < 0)
        return CRYPT_ERR;
    if (register_hash(&sha256_desc) < 0)
        return CRYPT_ERR;
    if (register_hash(&sha384_desc) < 0)
        return CRYPT_ERR;
    if (register_hash(&sha512_desc) < 0)
        return CRYPT_ERR;

    return CRYPT_OK;
}

/*
 * hash functions
 */

const struct crypt_hash_def *hash_lookup(const char *name)
{
    uint32_t i;

    if (!name || name[0] == '\0')
        return NULL;

    /* NOTE: this isn't very elegant, but ok for small hash lists */
    for (i = 0; i < sizeof(hash_list)/sizeof(struct crypt_hash_def); i++)
    {
        if (!tb_strcmp(name, hash_list[i].name))
            return &hash_list[i];
    }

    return NULL;
}

int hash_init(struct crypt_hash_state *state, const char *name)
{
    int rc;

    if (!state || !name || name[0] == '\0')
        return CRYPT_EINVAL;

    state->def = hash_lookup(name);
    if (!state->def)
        return CRYPT_ERR;

    switch (state->def->token)
    {
    case CRYPT_HASH_MD5:
        rc = md5_init(&state->state);
        break;
    case CRYPT_HASH_SHA1:
        rc = sha1_init(&state->state);
        break;
    case CRYPT_HASH_SHA256:
        rc = sha256_init(&state->state);
        break;
    case CRYPT_HASH_SHA384:
        rc = sha384_init(&state->state);
        break;
    case CRYPT_HASH_SHA512:
        rc = sha512_init(&state->state);
        break;
    default:
        return CRYPT_ERR;
    }
    if (rc != 0)
        return CRYPT_ERR;

    return CRYPT_OK;
}

int hash_data(struct crypt_hash_state *state, void *blob, uint32_t blob_len)
{
    int rc;

    if (!state || !blob || blob_len == 0)
        return CRYPT_EINVAL;

    switch (state->def->token)
    {
    case CRYPT_HASH_MD5:
        rc = md5_process(&state->state, blob, blob_len);
        break;
    case CRYPT_HASH_SHA1:
        rc = sha1_process(&state->state, blob, blob_len);
        break;
    case CRYPT_HASH_SHA256:
        rc = sha256_process(&state->state, blob, blob_len);
        break;
    case CRYPT_HASH_SHA384:
        rc = sha384_process(&state->state, blob, blob_len);
        break;
    case CRYPT_HASH_SHA512:
        rc = sha512_process(&state->state, blob, blob_len);
        break;
    default:
        return CRYPT_ERR;
    }
    if (rc != 0)
        return CRYPT_ERR;

    return blob_len;
}

int hash_done(struct crypt_hash_state *state, void *blob, uint32_t blob_len)
{
    int rc;

    if (!state || !blob || blob_len == 0)
        return CRYPT_EINVAL;

    switch (state->def->token)
    {
    case CRYPT_HASH_MD5:
        if (blob_len < state->def->len)
            return CRYPT_EINVAL;
        rc = md5_done(&state->state, blob);
        break;
    case CRYPT_HASH_SHA1:
        if (blob_len < state->def->len)
            return CRYPT_EINVAL;
        rc = sha1_done(&state->state, blob);
        break;
    case CRYPT_HASH_SHA256:
        if (blob_len < state->def->len)
            return CRYPT_EINVAL;
        rc = sha256_done(&state->state, blob);
        break;
    case CRYPT_HASH_SHA384:
        if (blob_len < state->def->len)
            return CRYPT_EINVAL;
        rc = sha384_done(&state->state, blob);
        break;
    case CRYPT_HASH_SHA512:
        if (blob_len < state->def->len)
            return CRYPT_EINVAL;
        rc = sha512_done(&state->state, blob);
        break;
    default:
        return CRYPT_ERR;
    }
    if (rc != 0)
        return CRYPT_ERR;

    return state->def->len;
}

uint32_t hash_len_name(const char *name)
{
    const struct crypt_hash_def *def;

    if (!name || name[0] == '\0')
        return 0;

    def = hash_lookup(name);
    if (!def)
        return 0;

    return def->len;
}

/*
 * pk
 */

const struct crypt_hash_def *pk_alg_hash(const char *pk_alg)
{
    uint32_t i;
    uint32_t pk_hash_len;

    /* NOTE: we assume pk_alg is of the format "<hash>_<cipher>" */

    /* we might not always have strstr/strchr/etc. */
    pk_hash_len = 0;
    while (pk_alg[pk_hash_len] != '\0' && pk_alg[pk_hash_len] != '_')
        pk_hash_len++;
    if (pk_alg[pk_hash_len] != '_')
        return NULL;

    /* stolen from hash_lookup() */
    for (i = 0; i < sizeof(hash_list)/sizeof(struct crypt_hash_def); i++)
    {
        if (pk_hash_len != tb_strlen(hash_list[i].name))
            continue;
        if (!tb_strncmp(pk_alg, hash_list[i].name, pk_hash_len - 1))
            return &hash_list[i];
    }

    return NULL;
}

static int _pk_import_rsa_key(rsa_key *key,
                              const unsigned char *key_blob, uint32_t key_len)
{
    int rc;

    /* NOTE: you can use the following openssl command to get the key/cert
     *       in x509/der format:
     *         # openssl x509 -outform DER -in cert.pem -out cert.x509
     */

    /* import the rsa key in x.509 format */
    rc = rsa_import_x509(key_blob, key_len, key);
    if (rc == 0)
        return CRYPT_OK;

    /* import the rsa key, either raw or openssl der format */
    rc = rsa_import(key_blob, key_len, key);
    if (rc == 0)
        return CRYPT_OK;

    return CRYPT_ERR;
}

int pk_verify_pkcs1_v15(const char *digest_name,
                        const unsigned char *digest_blob, uint32_t digest_len,
                        const unsigned char *sig_blob, uint32_t sig_len,
                        const unsigned char *key_blob, uint32_t key_len)
{
    int rc;
    int result;
    int digest_idx;
    rsa_key key;

    /* import the rsa key */
    rc = _pk_import_rsa_key(&key, key_blob, key_len);
    if (rc < 0)
        return rc;

    /* lookup the hash function in tomcrypt */
    digest_idx = find_hash(digest_name);
    if (digest_idx < 0)
    {
        rc = CRYPT_ERR;
        goto free_key;
    }

    /* verify the signature */
    rc = rsa_verify_hash_ex(sig_blob, sig_len,
                            digest_blob, digest_len,
                            LTC_PKCS_1_V1_5,
                            digest_idx,
                            0, /* salt_len is ignored for pkcs #1 v1.5 */
                            &result,
                            &key);
    if (rc != 0)
        rc = CRYPT_ERR;
    else if (result != 1)
        rc = CRYPT_FAIL;
    else
        rc = CRYPT_OK;

free_key:
    rsa_free(&key);
    return rc;
}
