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

#include <types.h>
#include <string.h>

#include "asn1.h"
#include "asn1-oid.h"
#include "pkcs7.h"
#include "pkcs1.h"
#include "crypt.h"

int pkcs7_signeddata_parse(struct pkcs7_signeddata *pkcs7,
                           unsigned char *blob, uint32_t blob_len)
{
    int rc;
    uint32_t offset_nxt;
    struct asn1_hndl asn1;
    struct asn1_value asn1_val;
    const struct oid_def *oid_def;
    struct pkcs7_digest *digest;
    struct pkcs7_signature *signature;
    struct pkcs7_mscodesign *contentinfo;

    /* TODO: the asn1/pkcs parser below is very crude and there are some bits
     *       which are based only by the samples used in testing, not the
     *       actual spec; this entire function could use some work to make it
     *       better
     */

    /* TODO: we should verify/cross-check a lot of the fields in here, see
     *       the msft authenticode spec for more details */

    /* NOTE: the pecoff signed image verification is a bit messy, but the
     *       basic idea is that the contentInfo ("[ msindirobj ]") digest
     *       is used to verify the kernel image (see the
     *       pecoff.c:pe_ac_digest_verify(...) function) and the
     *       contentInfo blob is verified by the digest stored in the
     *       authenticatedAttributes (see the
     *       pkcs7_signeddata_content_verify(...) function), and the
     *       authenticatedAttributes blob is finally verified by the
     *       signature stored at the end of the file in the
     *       signerInfos encryptedDigest.
     *
     *       unfortunately the exact fields/offset to use for the digests
     *       above are unclear in the specs, but the process used in the
     *       code below has shown to work on signed CentOS 7.x and Fedora
     *       kernels.
     */

    if (!pkcs7 || !blob || blob_len == 0)
        return PKCS7_ERR;

    digest = &pkcs7->digest;
    signature = &pkcs7->signature;
    contentinfo = &pkcs7->contentinfo;

    rc = asn1_load(blob, blob_len, &asn1);
    if (rc < 0)
        return rc;
    while (asn1_value(&asn1, &asn1_val) == 0)
    {
        if ((asn1_val.tag & ASN1_TAG_MASK) == tag_seq)
        {
            asn1_next(&asn1);

            /*
             * "version Version"
             *
             * we only support version 0x01
             */

            /* INTEGER: 0x01 */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_int)
                continue;
            if (asn1_val.value[0] != 0x01)
                continue;

            /*
             * "digestAlgorithms DigestAlgorithmIdentifiers"
             *
             * the spec only allows for one digest algorithm
             */

            /* SET */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_set)
                continue;

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: [ <hash> ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def)
                continue;
            contentinfo->hash_name = oid_def->name;

            /* NULL */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_null)
                continue;

            /*
             * "contentInfo ContentInfo"
             *
             * the content is optional, but in our case we require
             * it since it is the digest (SpcIndirectDataContent)
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: [ ms_indirobj ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def ||
                    tb_strcmp(oid_def->name, "ms_indirobj") != 0)
                continue;

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *
             */

            /* cont [ 00 ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) != class_cont)
                continue;
            if ((asn1_val.tag & ASN1_TAG_MASK) != 0x00)
                continue;

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;
            asn1_blob_set(&contentinfo->blob, &asn1_val);

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *     "data SpcAttributeTypeAndOptionalValue"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: [ ms_codesign ] (CentOS 7.x, ?!) */
            /* OID: [ ms_spcimgdataobj ] (spec,F30,others)*/
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def ||
                    (tb_strcmp(oid_def->name, "ms_codesign") != 0 &&
                     tb_strcmp(oid_def->name, "ms_spcimgdataobj") != 0))
                continue;

            /* NOTE: the "ms_codesign" OID isn't defined here in
             *       the spec, but it is present and may help
             *       explain some of the odd types in
             *       "file SpcLink" below
             * NOTE: the "ms_codesign" OID appears to be limited,
             *       the proper "ms_spcimgdataobj" appears in newer
             *       signed kernels
             */

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *     "data SpcAttributeTypeAndOptionalValue"
             *       "value SpcPeImageData"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *     "data SpcAttributeTypeAndOptionalValue"
             *       "value SpcPeImageData"
             *         "flags SpcPeImageFlags"
             *
             */

            /* BITSTR */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            /* this is odd - this a flag field which indicates
             * what portions of the file are hashed, but according
             * to the spec the values here should be ignored */
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_bitstr)
                continue;

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *     "data SpcAttributeTypeAndOptionalValue"
             *       "value SpcPeImageData"
             *         "file SpcLink"
             *
             * technically optional according to asn1/pkcs, but
             * always present for pecoff purposes
             */

            /* NOTE: i can't explain the types below, but see the
             *       note above regarding "ms_codesign"
             */

            /* cont [ 00 ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) != class_cont)
                continue;
            if ((asn1_val.tag & ASN1_TAG_MASK) != 0x00)
                continue;

            /* cont [ 02 ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) != class_cont)
                continue;
            if ((asn1_val.tag & ASN1_TAG_MASK) != 0x02)
                continue;

            /* cont [ 00 ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) != class_cont)
                continue;
            if ((asn1_val.tag & ASN1_TAG_MASK) != 0x00)
                continue;

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *     "messageDigest DigestInfo"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /*
             * "digestAlgorithm  AlgorithmIdentifier"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: [ <hash> ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def)
                continue;
            digest->hash_name = oid_def->name;

            /* NULL */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_null)
                continue;

            /*
             * "contentInfo ContentInfo"
             *   "content SpcIndirectDataContent"
             *     "messageDigest DigestInfo"
             *       "digest OCTETSTRING"
             *
             * this is the pecoff digest that we care about
             */

            /* OCTSTR */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_octstr)
                continue;
            if (asn1_val.len_val !=
                    hash_len_name(digest->hash_name))
                return PKCS7_ERR;
            asn1_blob_set(&digest->digest, &asn1_val);

            /*
             * "certificates
             *   [0] IMPLICIT ExtendedCertificatesAndCertificates
             *   OPTIONAL"
             *
             * this is optional according to the spec
             */

            /* cont [ 00 ] */
            if (asn1_value(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) == class_cont &&
                    (asn1_val.tag & ASN1_TAG_MASK) == 0x00)
            {
                rc = pkcs1_import(asn1_val.value, asn1_val.len_val,
                                  CERT_F_NONE);
                if (rc < 0)
                    return PKCS7_ERR;
                /* we imported the certs already, skip 'em */
                asn1_next_constr(&asn1);
            }

            /*
             * "Crls
             *   [1] IMPLICIT CertificateRevocationLists
             *   OPTIONAL"
             *
             * this is optional according to the spec
             */

            /* cont [ 01 ] */
            if (asn1_value(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) == class_cont &&
                (asn1_val.tag & ASN1_TAG_MASK) == 0x01)
            {
                /* NOTE: we are not parsing these certs */
                asn1_next_constr(&asn1);
            }

            /*
             * "signerInfos SignerInfos"
             *
             * a set of signers, but with a signed pecoff file
             * there will only ever be one signer in this set
             */

            /* SET */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_set)
                continue;

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /*
             * "signerInfos SignerInfos"
             *   "version Version"
             *
             * we only support version 0x01
             */

            /* INTEGER: 0x01 */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_int)
                continue;
            if (asn1_val.value[0] != 0x01)
                continue;

            /*
             * "signerInfos SignerInfos"
             *   "issuerAndSerialNumber IssuerAndSerialNumber"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* SEQUENCE */
            if (asn1_value(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;
            signature->signer.data = asn1_val.raw;
            signature->signer.len = asn1_val.len_hdr + asn1_val.len_val;

            /* we are going to parse through this set looking for a
            * "[ commonname ]" */
            offset_nxt = asn1.offset_nxt_constr;
            asn1_next(&asn1);
            while (asn1.offset_cur < offset_nxt)
            {
                /* skip ahead if we already found it */
                if (signature->signer_cn.data)
                {
                    asn1_skip(&asn1);
                    continue;
                }

                /* TODO: decide how much we care about a missing CN */

                /* SET */
                if (asn1_value_next(&asn1, &asn1_val) != 0)
                    return PKCS7_ERR;
                if ((asn1_val.tag & ASN1_TAG_MASK) != tag_set)
                    continue;

                /* SEQUENCE */
                if (asn1_value_next(&asn1, &asn1_val) != 0)
                    return PKCS7_ERR;
                if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                    continue;

                /* OID: [ commonname ] */
                if (asn1_value_next(&asn1, &asn1_val) != 0)
                    return PKCS7_ERR;
                if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                    continue;
                oid_def = asn1_oid_lookup_asn1(&asn1_val);
                if (!oid_def || tb_strcmp(oid_def->name, "commonname") != 0)
                    continue;

                /* PRINTSTR|UTF8STR */
                /* TODO: look into supporting more types */
                if (asn1_value_next(&asn1, &asn1_val) != 0)
                    return PKCS7_ERR;
                switch (asn1_val.tag & ASN1_TAG_MASK)
                {
                case tag_printstr:
                case tag_utf8str:
                    asn1_blob_set(&signature->signer_cn,
                                  &asn1_val);
                    break;
                default:
                    continue;
                }
            }

            /* INTEGER */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_int)
                continue;
            asn1_blob_set(&signature->signer_serial, &asn1_val);

            /*
             * "signerInfos SignerInfos"
             *   "digestAlgorithm DigestAlgorithmIdentifier"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: [ <hash> ] */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def)
                continue;
            signature->hash_name = oid_def->name;

            /* NULL */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_null)
                continue;

            /*
             * "signerInfos SignerInfos"
             *   "authenticatedAttributes
             *     [0] IMPLICIT Attributes OPTIONAL"
             *
             * these may be optional, but we need them
             */

            /* cont [ 00 ] */
            if (asn1_value(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag_raw & ASN1_CLASS_MASK) == class_cont &&
                (asn1_val.tag & ASN1_TAG_MASK) == 0x00)
            {
                /* NOTE: technically parsing some of this is
                 *       dependent on the ms authenticode spec,
                 *       and not the general pkcs7 spec, but
                 *       we'll do it here because it is easier
                 *       and this isn't really general purpose
                 *       code anyway */

                /* store a pointer to this for later use */
                signature->authattr.data = asn1_val.raw;
                signature->authattr.len = asn1_val.len_hdr +
                                          asn1_val.len_val;
                /* we are going to parse through the rest of
                 * this field looking for a "[ msgdigest ]" */
                offset_nxt = asn1.offset_nxt_constr;
                asn1_next(&asn1);
                while (asn1.offset_cur < offset_nxt)
                {
                    /* skip ahead if we already found it */
                    if (contentinfo->digest.data)
                    {
                        asn1_skip(&asn1);
                        continue;
                    }

                    /* [ msgdigest ] ? */
                    if (asn1_value_next(&asn1, &asn1_val) != 0)
                        return PKCS7_ERR;
                    if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                        continue;
                    oid_def = asn1_oid_lookup_asn1(&asn1_val);
                    if (!oid_def || tb_strcmp(oid_def->name, "msgdigest") != 0)
                        continue;

                    /* found it */

                    /* SET */
                    if (asn1_value_next(&asn1, &asn1_val) != 0)
                        return PKCS7_ERR;
                    if ((asn1_val.tag & ASN1_TAG_MASK) != tag_set)
                        return PKCS7_ERR;
                    /* OCTSTR */
                    if (asn1_value_next(&asn1, &asn1_val) != 0)
                        return PKCS7_ERR;
                    if ((asn1_val.tag & ASN1_TAG_MASK) != tag_octstr)
                        return PKCS7_ERR;
                    if (asn1_val.len_val !=
                            hash_len_name(digest->hash_name))
                        return PKCS7_ERR;
                    asn1_blob_set(&contentinfo->digest, &asn1_val);
                }
            }
            else
            {
                signature->authattr.data = NULL;
                signature->authattr.len = 0;
                contentinfo->digest.data = NULL;
                contentinfo->digest.len = 0;
            }

            /*
             * "signerInfos SignerInfos"
             *   "digestEncryptionAlgorithm
             *     DigestEncryptionAlgorithmIdentifier"
             *
             */

            /* SEQUENCE */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_seq)
                continue;

            /* OID: [ rsaenc ] */
            /* TODO: support different encryption algorithms? */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_oid)
                continue;
            oid_def = asn1_oid_lookup_asn1(&asn1_val);
            if (!oid_def ||
                    tb_strcmp(oid_def->name, "rsaenc") != 0)
                continue;
            signature->enc_name = oid_def->name;

            /* NULL */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_null)
                continue;

            /*
             * "signerInfos SignerInfos"
             *   "encryptedDigest EncryptedDigest"
             *
             * this is the encrypted digest (signature) we care
             * about
             */

            /* OCTSTR */
            if (asn1_value_next(&asn1, &asn1_val) != 0)
                return PKCS7_ERR;
            if ((asn1_val.tag & ASN1_TAG_MASK) != tag_octstr)
                continue;
            asn1_blob_set(&signature->signature, &asn1_val);

            /*
             * "signerInfos SignerInfos"
             *   "unauthenticatedAttributes
             *     [1] IMPLICIT AttributesOptional"
             *
             * we don't care about these attributes, if present,
             * or anything which may follow
             */

            /* TODO: we should probably parse these if present */

            return PKCS7_OK;
        }
        else
            asn1_skip(&asn1);
    }

    return PKCS7_ERR;
}

int pkcs7_signeddata_sig_verify(struct pkcs7_signeddata *pkcs7,
                                const unsigned char *key_blob,
                                uint32_t key_len)
{
    int rc;
    struct crypt_hash_state state;
    unsigned char authattr_tag;
    unsigned char digest[CRYPT_HASH_LEN_MAX];
    uint32_t digest_len = CRYPT_HASH_LEN_MAX;

    /* hash the authenticated attributes */
    rc = hash_init(&state, pkcs7->signature.hash_name);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    /* NOTE: yes, we really do need to replace the implicit tag with an
     *       explicit set tag because pkcs7 is awful */
    authattr_tag=0x31;
    rc = hash_data(&state, &authattr_tag, 1);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    rc = hash_data(&state,
                   &pkcs7->signature.authattr.data[1],
                   pkcs7->signature.authattr.len - 1);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    rc = hash_done(&state, digest, digest_len);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    digest_len = rc;

    /* verify the signature */
    rc = pk_verify_pkcs1_v15(pkcs7->signature.hash_name,
                             digest, digest_len,
                             pkcs7->signature.signature.data,
                             pkcs7->signature.signature.len,
                             key_blob, key_len);
    if (rc == CRYPT_OK)
    {
        pkcs7->signature.verified = PKCS7_V_PASS;
        return PKCS7_OK;
    }

    pkcs7->signature.verified = PKCS7_V_FAIL;
    return PKCS7_CRYPTFAIL;
}

int pkcs7_signeddata_content_verify(struct pkcs7_signeddata *pkcs7)
{
    int rc;
    struct crypt_hash_state state;
    unsigned char digest[CRYPT_HASH_LEN_MAX];
    uint32_t digest_len = CRYPT_HASH_LEN_MAX;

    /* hash the contentinfo */
    rc = hash_init(&state, pkcs7->contentinfo.hash_name);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    rc = hash_data(&state,
                   pkcs7->contentinfo.blob.data,
                   pkcs7->contentinfo.blob.len);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    rc = hash_done(&state, digest, digest_len);
    if (rc < 0)
        return PKCS7_CRYPTERR;
    digest_len = rc;

    if (digest_len == pkcs7->contentinfo.digest.len &&
            tb_memcmp(digest, pkcs7->contentinfo.digest.data, digest_len) == 0)
    {
        pkcs7->contentinfo.verified = PKCS7_V_PASS;
        return PKCS7_OK;
    }

    pkcs7->contentinfo.verified = PKCS7_V_FAIL;
    return PKCS7_CRYPTFAIL;
}
