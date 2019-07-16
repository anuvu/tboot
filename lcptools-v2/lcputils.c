/*
 * lcputils.c: misc. LCP helper fns
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <safe_lib.h>
#include <snprintf_s.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"

void ERROR(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void LOG(const char *fmt, ...)
{
    va_list ap;

    if ( verbose ) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

void DISPLAY(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    strcpy_s(dst, siz, src);
    return strnlen_s(dst, siz);
}

void print_hex(const char *prefix, const void *data, size_t n)
{
#define NUM_CHARS_PER_LINE    20
    unsigned int i = 0;
    while ( i < n ) {
        if ( i % NUM_CHARS_PER_LINE == 0 && prefix != NULL )
            DISPLAY("%s", prefix);
        DISPLAY("%02x ", *(uint8_t *)data++);
        i++;
        if ( i % NUM_CHARS_PER_LINE == 0 )
            DISPLAY("\n");
    }
    if ( i % NUM_CHARS_PER_LINE != 0 )
        DISPLAY("\n");
}

void parse_comma_sep_ints(char *s, uint16_t ints[], unsigned int *nr_ints)
{
    unsigned int nr = 0;

    while ( true ) {
        char *str = strsep(&s, ",");
        if ( str == NULL || nr == *nr_ints )
            break;
        ints[nr++] = strtoul(str, NULL, 0);
    }
    if ( nr == *nr_ints )
        ERROR("Error: too many items in list\n");
    *nr_ints = nr;
    return;
}

void *read_file(const char *file, size_t *length, bool fail_ok)
{
    LOG("[read_file]\n");
    LOG("read_file: filename=%s\n", file);
    FILE *fp = fopen(file, "rb");
    if ( fp == NULL ) {
        if ( !fail_ok )
            ERROR("Error: failed to open file %s: %s\n", file,
                    strerror(errno));
        return NULL;
    }

    /* find size */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);

    void *data = malloc(len);
    if ( data == NULL ) {
        ERROR("Error: failed to allocate %d bytes memory\n", len);
        fclose(fp);
        return NULL;
    }

    if ( fread(data, len, 1, fp) != 1 ) {
        ERROR("Error: reading file %s\n", file);
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    if ( length != NULL )
        *length = len;
    LOG("read file succeed!\n");
    return data;
}

bool write_file(const char *file, const void *data, size_t size)
{
    LOG("[write_file]\n");
    FILE *fp = fopen(file, "wb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s for writing: %s\n",
                file, strerror(errno));
        return false;
    }
    if ( fwrite(data, size, 1, fp) != 1 ) {
        ERROR("Error: writing file %s\n", file);
        fclose(fp);
        return false;
    }
    fclose(fp);
    LOG("write file succeed!\n");
    return true;
}

bool parse_line_hashes(const char *line, tb_hash_t *hash, uint16_t alg)
{
    /* skip any leading whitespace */
    while ( *line != '\0' && isspace(*line) )
        line++;

    /* rest of line is hex of hash */
    unsigned int i = 0;
    while ( *line != '\0' && *line != '\n' ) {
        char *next;
        switch (alg) {
        case TPM_ALG_SHA1:
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA256:
            hash->sha256[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA384:
            hash->sha384[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        default:
            ERROR("Error: unsupported alg: 0x%x\n",alg);
            return false;
        }
        if ( next == line )      /* done */
            break;
        line = next;
        /* spaces at end cause strtoul() to interpret as 0, so skip them */
        while ( *line != '\0' && !isxdigit(*line) )
            line++;
    }

    if ( i != get_hash_size(alg) ) {
        ERROR("Error: incorrect number of chars for hash\n");
        return false;
    }

    return true;
}

bool parse_file(const char *filename, bool (*parse_line)(const char *line))
{
    if ( filename == NULL || parse_line == NULL )
        return false;

    LOG("reading hashes file %s...\n", filename);

    FILE *fp = fopen(filename, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s (%s)\n", filename, strerror(errno));
        return false;
    }

    static char line[1024];
    while ( true ) {
        char *s = fgets(line, sizeof(line), fp);

        if ( s == NULL ) {
            fclose(fp);
            return true;
        }

        LOG("read line: %s", line);

        if ( !(*parse_line)(line) ) {
            fclose(fp);
            return false;
        }
    }

    fclose(fp);
    return false;
}

const char *hash_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_SHA1:
        return "sha1";
    case TPM_ALG_SHA256:
        return "sha256";
    case TPM_ALG_SHA384:
        return "sha384";
    case TPM_ALG_SHA512:
        return "sha512";
    case TPM_ALG_SM3_256:
        return "sm3";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

const char *sig_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_RSASSA:
        return "rsa";
    case TPM_ALG_ECDSA:
        return "ecdsa";
    case TPM_ALG_SM2:
        return "sm2";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

uint16_t str_to_hash_alg(const char *str) 
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_SM3_256;
    else
        return  TPM_ALG_NULL;
}

uint16_t str_to_lcp_hash_mask(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_MASK_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_MASK_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_MASK_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_MASK_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_MASK_SM3_256;
    else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2))
        return strtoul(str, NULL, 0);
    else
        return  TPM_ALG_MASK_NULL;
}

uint16_t str_to_sig_alg(const char *str, const uint16_t version)
{
    LOG("str_to_sig_alg:version=%x\n",version);
    if( version == LCP_TPM12_POLICY_LIST_VERSION) {
        if (strcmp(str,"rsa") == 0)
            return LCP_POLSALG_RSA_PKCS_15;
        else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2))
            return strtoul(str, NULL, 0);
        else 
            return LCP_POLSALG_NONE;
    }
    else if( version == LCP_TPM20_POLICY_LIST_VERSION) {
        if( strcmp(str,"rsa") == 0)
            return TPM_ALG_RSASSA;
        else if ( strcmp(str,"ecdsa") == 0) {
            LOG("str_to_sig_alg: sig_alg == ecdsa\n");
            return TPM_ALG_ECDSA;
        }
        else if ( strcmp(str,"sm2") == 0)
            return TPM_ALG_SM2;
        else 
            return TPM_ALG_NULL;
    }
    else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2))
        return strtoul(str, NULL, 0);
    else
        return TPM_ALG_NULL;
}
uint32_t str_to_sig_alg_mask(const char *str, const uint16_t version)
{
    LOG("str_to_sig_alg_mask:version=%x\n",version);
    uint16_t lcp_major_ver = version & 0xFF00;
    if( lcp_major_ver == LCP_VER_2_0 ) {
        //signature algorithm mask is undefined in LCPv2
        return SIGN_ALG_MASK_NULL;
    }
    else if( lcp_major_ver == LCP_VER_3_0) {
        if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2)){
            return strtoul(str, NULL, 0);
        }
        else{
            //mask must be specified explicitly, no string parsing yet
            return SIGN_ALG_MASK_NULL;
        }
    }
    else 
        return SIGN_ALG_MASK_NULL;
}
uint16_t str_to_pol_ver(const char *str)
{
    if( strcmp(str,"2.0") == 0)
       return LCP_VER_2_0;
    else if ( strcmp(str,"3.0") == 0)
        return LCP_VER_3_0;
    else if ( strcmp(str,"3.1") == 0)
        return LCP_VER_3_1;
    else 
        return LCP_VER_NULL;
}

uint16_t convert_hash_alg_to_mask(uint16_t hash_alg)
{
    LOG("convert_hash_alg_to_mask hash_alg = 0x%x\n", hash_alg);
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return TPM_ALG_MASK_SHA1;
    case TPM_ALG_SHA256:
        return TPM_ALG_MASK_SHA256;
    case TPM_ALG_SHA384:
        return TPM_ALG_MASK_SHA384;
    case TPM_ALG_SHA512:
        return TPM_ALG_MASK_SHA512;
    case TPM_ALG_SM3_256:
        return TPM_ALG_MASK_SM3_256;
    default:
        return 0;
    }
    return 0;
}

size_t get_lcp_hash_size(uint16_t hash_alg)
{
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256:
        return SHA256_DIGEST_SIZE;
    case TPM_ALG_SHA384:
        return SHA384_DIGEST_SIZE;
    case TPM_ALG_SHA512:
        return SHA512_DIGEST_SIZE;
    case TPM_ALG_SM3_256:
        return SM3_256_DIGEST_SIZE;
    default:
        return 0;
    }
    return 0;
}

bool verify_signature(const uint8_t *data, size_t data_size,
        const uint8_t *pubkey, size_t pubkey_size,
        const uint8_t *sig, bool is_sig_little_endian)
{
    LOG("[verify_signature]\n");
    unsigned int i;

    /* policy key is little-endian and openssl wants big-endian, so reverse */
    uint8_t key[pubkey_size];
    for ( i = 0; i < pubkey_size; i++ )
        key[i] = *(pubkey + (pubkey_size - i - 1));

    /* create RSA public key struct */
    RSA *rsa_pubkey = RSA_new();
    if ( rsa_pubkey == NULL ) {
        ERROR("Error: failed to allocate key\n");
        return false;
    }

    BIGNUM *modulus = BN_bin2bn(key, pubkey_size, NULL);
    BIGNUM *exponent = BN_new();

    /* uses fixed exponent (LCP_SIG_EXPONENT) */
    char exp[32];
    snprintf_s_i(exp, sizeof(exp), "%u", LCP_SIG_EXPONENT);
    BN_dec2bn(&exponent, exp);
    /* OpenSSL Version 1.1.0 and later don't allow direct access to RSA 
       stuct */ 
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_set0_key(rsa_pubkey, modulus, exponent, NULL); 
    #else
        rsa_pubkey->n = modulus;
        rsa_pubkey->e = exponent;
        rsa_pubkey->d = rsa_pubkey->p = rsa_pubkey->q = NULL;
    #endif

    uint16_t hashalg = TPM_ALG_SHA1;
    lcp_mle_element_t2 *mle;
    const lcp_policy_element_t *elt = ((lcp_policy_list_t2 *)data)->policy_elements;
    uint32_t type = elt->type;
    switch(type){
    case LCP_POLELT_TYPE_MLE2:
        mle = (lcp_mle_element_t2 *)elt->data;
        hashalg = mle->hash_alg;
        LOG("mle_hashalg = 0x%x\n",hashalg);
        break;
    default:
        LOG("unknown element type\n");
    }

    /* first create digest of data */
    tb_hash_t digest;
    if ( !hash_buffer(data, data_size, &digest, hashalg) ) {
        ERROR("Error: failed to hash list\n");
        RSA_free(rsa_pubkey);
        return false;
    }
    if ( verbose ) {
        LOG("digest: ");
        print_hex("", &digest, get_hash_size(hashalg));
    }

    /* sigblock is little-endian and openssl wants big-endian, so reverse */
    uint8_t sigblock[pubkey_size];
    if ( is_sig_little_endian ) {
        for ( i = 0; i < pubkey_size; i++ )
            sigblock[i] = *(sig + (pubkey_size - i - 1));
        sig = sigblock;
    }

    if ( verbose ) {
        /* raw decryption of sigblock */
        uint8_t unsig[pubkey_size];
        if ( RSA_public_decrypt(pubkey_size, sig, unsig, rsa_pubkey,
                    RSA_NO_PADDING) == -1 ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to decrypt sig: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
        }
        else {
            LOG("decrypted sig:\n");
            print_hex("", unsig, pubkey_size);
        }
    }

    switch(hashalg){
    case TPM_ALG_SHA1:
        /* verify digest */
        if ( !RSA_verify(NID_sha1, (const unsigned char *)&digest,
                    get_hash_size(hashalg), (uint8_t *)sig, pubkey_size,
                    rsa_pubkey) ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to verify list: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
            RSA_free(rsa_pubkey);
            return false;
        }
        break;

    case TPM_ALG_SHA256:
        /* verify digest */
        if ( !RSA_verify(NID_sha256, (const unsigned char *)&digest,
                    get_hash_size(hashalg), (uint8_t *)sig, pubkey_size,
                    rsa_pubkey) ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to verify list: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
            RSA_free(rsa_pubkey);
            return false;
        }
        break;

    case TPM_ALG_SHA384:
        /* verify digest */
        if ( !RSA_verify(NID_sha384, (const unsigned char *)&digest,
                    get_hash_size(hashalg), (uint8_t *)sig, pubkey_size,
                    rsa_pubkey) ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to verify list: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
            RSA_free(rsa_pubkey);
            return false;
        }
        break;

    case TPM_ALG_SHA512:
        /* verify digest */
        if ( !RSA_verify(NID_sha512, (const unsigned char *)&digest,
                    get_hash_size(hashalg), (uint8_t *)sig, pubkey_size,
                    rsa_pubkey) ) {
            ERR_load_crypto_strings();
            ERROR("Error: failed to verify list: %s\n", 
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_free_strings();
            RSA_free(rsa_pubkey);
            return false;
        }
        break;

    default :
        LOG("unknown hash alg\n");
        return false;
        RSA_free(rsa_pubkey);
    }

    RSA_free(rsa_pubkey);
    return true;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
