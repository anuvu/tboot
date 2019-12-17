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

#include <types.h>
#include <string.h>

#include "asn1.h"
#include "asn1-oid.h"
#include "pkcs1.h"
#include "crypt.h"

struct cert_db_entry
{
    uint32_t flags;
    struct pkcs1_cert_def cert;
};

#define CERT_DB_SIZE			16
static struct cert_db_entry cert_db[CERT_DB_SIZE];
static unsigned int cert_db_cnt = 0;

int pkcs1_count(void)
{
    return cert_db_cnt;
}

void pkcs1_foreachcert(uint32_t flags,
                       int (*callback)(struct pkcs1_cert_def *cert))
{
    unsigned int iter;
    struct cert_db_entry *entry;

    for (iter = 0; iter < cert_db_cnt; iter++)
    {
        entry = &cert_db[iter];
        if ((flags == 0) || CERT_F_TEST(entry->flags, flags))
        {
            if ((*callback)(&entry->cert))
                return;
        }
    }
}

static struct cert_db_entry *_pkcs1_search_subject(struct asn1_blob *subject)
{
    unsigned int iter;

    for (iter = 0; iter < cert_db_cnt; iter++)
    {
        if (!asn1_blob_cmp(&cert_db[iter].cert.subject, subject))
            return &cert_db[iter];
    }

    return NULL;
}

static struct cert_db_entry *_pkcs1_search(struct asn1_blob *subject,
        struct asn1_blob *serial)
{
    unsigned int iter;
    struct cert_db_entry *entry;

    for (iter = 0; iter < cert_db_cnt; iter++)
    {
        entry = &cert_db[iter];
        if (!asn1_blob_cmp(&entry->cert.serial, serial) &&
            !asn1_blob_cmp(&entry->cert.subject, subject))
            return entry;
    }
    return NULL;
}

struct pkcs1_cert_def *pkcs1_search_pkcs7signer(struct asn1_blob *subject,
        struct asn1_blob *serial)
{
    unsigned int iter;
    struct cert_db_entry *entry;

    for (iter = 0; iter < cert_db_cnt; iter++)
    {
        entry = &cert_db[iter];

        /* must be CERT_F_TRUSTED or both CERT_F_TRUSTCHAIN and
         * CERT_F_VERIFIED */
        if (!CERT_F_TEST(entry->flags, CERT_F_TRUSTED) &&
            !CERT_F_TEST(entry->flags, CERT_F_TRUSTCHAIN|CERT_F_VERIFIED))
            continue;

        if (!asn1_blob_cmp(&entry->cert.serial, serial) &&
            !asn1_blob_cmp(&entry->cert.issuer_cert->subject, subject))
            return &entry->cert;
    }
    return NULL;
}

struct pkcs1_cert_def *pkcs1_search_trustroot(struct pkcs1_cert_def *cert)
{
    struct cert_db_entry *entry;

    if (!cert)
        return NULL;
    entry = container_of(cert, struct cert_db_entry, cert);

    while (entry)
    {
        if (CERT_F_TEST(entry->flags, CERT_F_TRUSTED))
            return &entry->cert;
        entry = container_of(entry->cert.issuer_cert,
                             struct cert_db_entry, cert);
    }

    return NULL;
}

static int _pkcs1_verify_cert(struct pkcs1_cert_def *cert,
                              struct pkcs1_cert_def *issuer)
{
    int rc;
    const struct crypt_hash_def *digest_def;
    unsigned char digest[CRYPT_HASH_LEN_MAX];
    struct crypt_hash_state hash;

    /* hash the certificate */
    digest_def = pk_alg_hash(cert->signature_alg);
    if (!digest_def)
        return PKCS1_CRYPTERR;
    rc = hash_init(&hash, digest_def->name);
    if (rc < 0)
        return PKCS1_CRYPTERR;
    rc = hash_data(&hash, cert->cert.data, cert->cert.len);
    if (rc < 0)
        return PKCS1_CRYPTERR;
    rc = hash_done(&hash, digest, digest_def->len);
    if (rc < 0)
        return PKCS1_CRYPTERR;

    /* verify the signature */
    rc = pk_verify_pkcs1_v15(digest_def->name, digest, digest_def->len,
                             cert->signature.data,
                             cert->signature.len,
                             issuer->raw.data,
                             issuer->raw.len);
    if (rc == CRYPT_OK)
        return PKCS1_OK;

    return PKCS1_CRYPTFAIL;
}

static void _pkcs1_update_trust(void)
{
    int rc;
    unsigned int changed;
    unsigned int iter;
    struct cert_db_entry *cert;
    struct cert_db_entry *issuer;

    /* we might be running on a system with a limited stack so let's
     * not do the obvious recursive certificate checks and simply loop
     * through the db until the trust is no longer changing; since we
     * have a relatively small number of certs, this shouldn't be terrible */

    do
    {
        changed = 0;
        for (iter = 0; iter < cert_db_cnt; iter++)
        {
            cert = &cert_db[iter];

            /* skip certs we've already verified */
            if (CERT_F_TEST(cert->flags, CERT_F_VERIFIED))
                continue;

            /* look up the issuer by subject */
            issuer = _pkcs1_search_subject(&cert->cert.issuer);
            /* only verify against CERT_F_VERIFIED certs or ourselves if we
             * are self-signed */
            if (!issuer ||
                (!CERT_F_TEST(issuer->flags, CERT_F_VERIFIED) &&
                 issuer != cert))
                continue;

            rc = _pkcs1_verify_cert(&cert->cert, &issuer->cert);
            if (rc == PKCS1_OK)
            {
                /* set the issuer pointer */
                cert->cert.issuer_cert = &issuer->cert;

                /* update the flags */
                cert->flags |= CERT_F_VERIFIED;
                if (CERT_F_TESTANY(issuer->flags,
                                   CERT_F_TRUSTED|CERT_F_TRUSTCHAIN))
                    cert->flags |= CERT_F_TRUSTCHAIN;

                /* we need to make at least one more pass */
                changed++;
            }
        }
    }
    while (changed);
}

int pkcs1_import(unsigned char *blob, uint32_t blob_len, uint32_t flags)
{
    int rc = PKCS1_ERR;
    int blob_length = blob_len;
    unsigned int cert_cnt_start;
    uint32_t offset_nxt;
    struct asn1_hndl asn1;
    struct asn1_value asn1_val;
    const struct oid_def *oid_def;
    struct cert_db_entry *c;
    struct cert_db_entry *orig;

    cert_cnt_start = cert_db_cnt;

    /* NOTE: https://tools.ietf.org/html/rfc5280 used as the reference */

    /* loop through the list of certificates */
    rc = asn1_load(blob, blob_len, &asn1);
    if (rc < 0)
        goto out;
    while (asn1_offset(&asn1) < blob_length)
    {
        /* start recording the certificate info in the db */
        if (cert_db_cnt + 1 >= CERT_DB_SIZE)
            goto err;
        c = &cert_db[cert_db_cnt];

        tb_memset(&cert_db[cert_db_cnt],
                  0x0, sizeof(struct cert_db_entry));

        /* TODO: ensure we verify *all* of cert fields that we care about */

        /*
         * certificate
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /* keep a pointer to the full certificate blob */
        c->cert.raw.data = asn1_val.raw;
        c->cert.raw.len = asn1_val.len_hdr + asn1_val.len_val;

        /*
         * "tbsCertificate TBSCertificate"
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /* keep a pointer to just the certificate */
        c->cert.cert.data = asn1_val.raw;
        c->cert.cert.len = asn1_val.len_hdr + asn1_val.len_val;

        /*
         * "tbsCertificate TBSCertificate"
         */

        /* cont [ 00 ] */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag_raw & ASN1_CLASS_MASK) != class_cont)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != 0x00)
            goto err;

        /*
         * "tbsCertificate TBSCertificate"
         *   "version [0] EXPLICIT Version DEFAULT v1"
         *
         *  NOTE: v1=0, v2=1, v3=2, ...
         */

        /* INTEGER */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_int)
            goto err;
        /* TODO: do we care about the version number? (see extensions below) */
        asn1_blob_set(&c->cert.version, &asn1_val);

        /*
         * "tbsCertificate TBSCertificate"
         *   "serialNumber CertificateSerialNumber"
         */

        /* INTEGER */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_int)
            goto err;
        asn1_blob_set(&c->cert.serial, &asn1_val);

        /*
         * "tbsCertificate TBSCertificate"
         *   "signature AlgorithmIdentifier"
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /* OID: <signature algorithm> */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
            continue;
        /* TODO: do we want to do something with this value? */

        /* optional parameters */
        /* NOTE: we blindly skip these */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;

        /*
         * "tbsCertificate TBSCertificate"
         *   "issuer Name"
         */

        /* SEQUENCE */
        if (asn1_value(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;
        c->cert.issuer.data = asn1_val.raw;
        c->cert.issuer.len = asn1_val.len_hdr + asn1_val.len_val;

        /* we are going to parse through this set looking for a
         * "[ commonname ]" */
        offset_nxt = asn1.offset_nxt_constr;
        asn1_next(&asn1);
        while (asn1.offset_cur < offset_nxt)
        {
            /* skip ahead if we already found it */
            if (c->cert.issuer_cn.data)
            {
                asn1_skip(&asn1);
                continue;
            }

            /* TODO: decide how much we care about a missing CN */

            /* SET */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_set)
                goto err;

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: <DN type> */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def || tb_strcmp(oid_def->name, "commonname") != 0)
                continue;

            /* PRINTSTR|UTF8STR */
            /* TODO: look into supporting more string types */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            switch (asn1_val.tag & ASN1_TAG_MASK)
            {
            case tag_printstr:
            case tag_utf8str:
                asn1_blob_set(&c->cert.issuer_cn, &asn1_val);
                break;
            default:
                continue;
            }
        }

        /*
         * "tbsCertificate TBSCertificate"
         *   "validity Validity"
         *
         * since we can't rely on a valid system clock, ignore the
         * time validity requirements
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /* UTCTIME: not before */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_utctime)
            goto err;

        /* UTCTIME: not after */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_utctime)
            goto err;

        /*
         * "tbsCertificate TBSCertificate"
         *   "subject Name"
         */

        /* SEQUENCE */
        if (asn1_value(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;
        c->cert.subject.data = asn1_val.raw;
        c->cert.subject.len = asn1_val.len_hdr + asn1_val.len_val;

        /* we are going to parse through this set looking for a
         * "[ commonname ]" */
        offset_nxt = asn1.offset_nxt_constr;
        asn1_next(&asn1);
        while (asn1.offset_cur < offset_nxt)
        {
            /* skip ahead if we already found it */
            if (c->cert.subject_cn.data)
            {
                asn1_skip(&asn1);
                continue;
            }

            /* TODO: decide how much we care about a missing CN */

            /* SET */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_set)
                goto err;

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                goto err;

            /* OID: <DN type> */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                goto err;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def || tb_strcmp(oid_def->name, "commonname") != 0)
                goto err;

            /* PRINTSTR|UTF8STR */
            /* TODO: look into supporting more string types */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                goto err;
            switch (asn1_val.tag & ASN1_TAG_MASK)
            {
            case tag_printstr:
            case tag_utf8str:
                asn1_blob_set(&c->cert.subject_cn, &asn1_val);
                break;
            default:
                continue;
            }
        }

        /*
         * "tbsCertificate TBSCertificate"
         *   "subjectPublicKeyInfo SubjectPublicKeyInfo"
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /*
         * "tbsCertificate TBSCertificate"
         *   "subjectPublicKeyInfo SubjectPublicKeyInfo"
         *     "algorithm AlgorithmIdentifier"
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /* OID */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
            goto err;
        /* TODO: support more than rsaenc? */
        oid_def = asn1_oid_lookup_asn1(&asn1_val);
        if (!oid_def || tb_strcmp(oid_def->name, "rsaenc") != 0)
            goto err;

        /* optional parameters */
        /* NOTE: we blindly skip these */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;

        /* BITSTR */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_bitstr)
            goto err;
        asn1_blob_set(&c->cert.key, &asn1_val);

        /*
         * "tbsCertificate TBSCertificate"
         *   "issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL"
         *   "subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL"
         *   "extensions [3] EXPLICIT Extensions OPTIONAL"
         *
         * if any are present the cert must be v2 or higher
         */

        if (asn1_value(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag_raw & ASN1_CLASS_MASK) != class_cont)
            goto err;
        switch (asn1_val.tag & ASN1_TAG_MASK)
        {
        case 0x01:
        case 0x02:
        case 0x03:
            /* TODO: verify the cert version */
            /* skip these fields */
            if (asn1_next_constr(&asn1) != 0)
                goto err;
            break;
        default:
            goto err;
        }

        /*
         * "signatureAlgorithm AlgorithmIdentifier"
         */

        /* SEQUENCE */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
            goto err;

        /* OID */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
            goto err;
        oid_def = asn1_oid_lookup_asn1(&asn1_val);
        if (!oid_def)
            goto err;
        c->cert.signature_alg = oid_def->name;

        /* optional parameters */
        /* TODO: we blindly skip these */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;

        /*
         * "signatureValue BIT STRING"
         */

        /* NOTE: in asn1 bitstrings the first byte indicates the amount
         *       of bit padding if the value length doesn't fall on an
         *       octet boundary; since this shouldn't be a problem for
         *       us here, fail if the first byte isn't 0x0 */

        /* BITSTR */
        if (asn1_value_next(&asn1, &asn1_val) != 0)
            goto err;
        if ((asn1_val.tag & ASN1_TAG_MASK) != tag_bitstr)
            goto err;
        if (asn1_val.value[0] != 0x0)
            goto err;
        c->cert.signature.data = &asn1_val.value[1];
        c->cert.signature.len = asn1_val.len_val - 1;

        /*
         * done
         */

        /* does this cert already exist in the certdb? */
        orig = _pkcs1_search(&c->cert.subject, &c->cert.serial);
        if (orig)
        {
            /* found one - make sure the certs are the same */
            if (!asn1_blob_cmp(&c->cert.raw, &orig->cert.raw))
            {
                /* duplicate - update the flags */
                orig->flags |= flags;
                continue;
            }

            /* subject name collision - fail */
            goto err;
        }
        else
        {
            /* no match - add this cert to the certdb */
            c->flags = flags;
            cert_db_cnt++;
        }
    };

out:
    if (cert_db_cnt != cert_cnt_start)
        _pkcs1_update_trust();
    return rc;
err:
    rc = PKCS1_ERR;
    goto out;
}
