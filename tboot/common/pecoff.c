/*
 * PECOFF functions
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
#include <tomcrypt.h>

#include "asn1.h"
#include "asn1-oid.h"
#include "pecoff.h"
#include "crypt.h"

#define PE_HDR_OFFSET(head, target) \
	(uint32_t)((unsigned char *)(target) - (unsigned char *)(head))

/* authenticode */

int pe_ac_digest_verify(struct pe_file *file)
{
    int rc;
    int k;
    uint32_t i, j;
    struct crypt_hash_state state;
    unsigned char hsh_value[64];
    uint32_t hash_len;
    uint32_t sec_addr_min;
    uint32_t extra_len;
    unsigned char *ptr;

    /* TODO: we should do a better job about checking boundaries */

    if (!file || !file->pkcs7.digest.hash_name)
        return PE_ERR;

    /* only attempt this once */
    if (file->pkcs7.digest.verified == PKCS7_V_PASS)
        return 0;
    else if (file->pkcs7.digest.verified == PKCS7_V_FAIL)
        return PE_CRYPTFAIL;

    rc = hash_init(&state, file->pkcs7.digest.hash_name);
    if (rc < 0)
        return PE_ERR;

    ptr = (unsigned char *)file->mz;
    rc = hash_data(&state, ptr, PE_HDR_OFFSET(ptr, file->pe));
    if (rc < 0)
        return PE_CRYPTERR;
    ptr += rc;

    rc = hash_data(&state, ptr, PE_HDR_OFFSET(ptr, &file->opt->chksum));
    if (rc < 0)
        return PE_CRYPTERR;
    ptr += rc + sizeof(file->opt->chksum);

    rc = hash_data(&state,
                   ptr, PE_HDR_OFFSET(ptr, file->ddir[PE_DDIR_ACT]));
    if (rc < 0)
        return PE_CRYPTERR;
    ptr += rc + sizeof(struct pe_hdr_ddir);

    rc = hash_data(&state, ptr,
                   PE_HDR_OFFSET(ptr, &file->raw_head[file->opt->hdr_len]));
    if (rc < 0)
        return PE_CRYPTERR;
    ptr += rc;

    hash_len = file->opt->hdr_len;
    sec_addr_min = 0;
    for (i = 0; i < file->sec_num; i++)
    {
        uint32_t tmp_addr = (uint32_t)-1;
        k = -1;

        /* find the next section according to data_addr */
        for (j = 0; j < file->sec_num; j++)
        {
            if (file->sec[j]->data_len > 0 &&
                    file->sec[j]->data_addr > sec_addr_min &&
                    file->sec[j]->data_addr < tmp_addr)
            {
                k = j;
                tmp_addr = file->sec[k]->data_addr;
            }
        }
        if (k == -1)
            continue;

        /* hash the section */
        rc = hash_data(&state,
                       &file->raw_head[file->sec[k]->data_addr],
                       file->sec[k]->data_len);
        if (rc < 0)
            return rc;
        hash_len += file->sec[k]->data_len;

        /* next */
        sec_addr_min = tmp_addr;
    }

    extra_len = file->raw_len - hash_len - file->ddir[PE_DDIR_ACT]->len;
    if (extra_len > 0)
    {
        /* TODO: handle extra data at the end of the image */
        return PE_ERR;
    }

    /*
     * authenticode digest calculation - stop
     */

    rc = hash_done(&state, hsh_value, sizeof(hsh_value));
    if (rc < 0)
        return PE_ERR;

    /* check the stored vs calculated digest */
    if (file->pkcs7.digest.digest.len != state.def->len)
        return PE_CRYPTFAIL;
    rc = tb_memcmp(file->pkcs7.digest.digest.data,
                   hsh_value, state.def->len);
    if (rc == 0)
    {
        file->pkcs7.digest.verified = PKCS7_V_PASS;
        rc = PE_OK;
    }
    else
    {
        file->pkcs7.digest.verified = PKCS7_V_FAIL;
        rc = PE_CRYPTFAIL;
    }

    return rc;
}

/* general pecoff */

int pe_parse(struct pe_file *file, unsigned char *blob, uint32_t blob_len)
{
    uint32_t i;
    uint32_t spot = 0;

    /* TODO: calculate the minimum pecoff file size */
    if (!blob || blob_len == 0 || !file)
        return PE_EINVAL;

    /* reset */
    tb_memset(file, 0x0, sizeof(*file));
    file->raw_head = blob;
    file->raw_len = blob_len;

    /* mz */
    if (spot + sizeof(struct pe_hdr_mz) > blob_len)
        return PE_ERR;
    file->mz = (struct pe_hdr_mz *)&blob[spot];
    spot += file->mz->pe_off;

    /* pe */
    if (spot + sizeof(struct pe_hdr_pe) > blob_len)
        return PE_ERR;
    file->pe = (struct pe_hdr_pe *)&blob[spot];
    spot += sizeof(struct pe_hdr_pe);

    /* peopt */
    if (spot + sizeof(struct pe_hdr_peopt) > blob_len)
        return PE_ERR;
    file->opt = (struct pe_hdr_peopt *)&blob[spot];
    spot += sizeof(struct pe_hdr_peopt);

    /* ddir */
    file->ddir_num = file->opt->ddir_num;
    if (file->ddir_num >= PE_DDIR_MAX)
        return PE_ERR;
    if (spot + (file->ddir_num * sizeof(struct pe_hdr_ddir)) > blob_len)
        return PE_ERR;
    for (i = 0; i < file->ddir_num; i++)
    {
        file->ddir[i] = (struct pe_hdr_ddir *)&blob[spot];
        spot += sizeof(struct pe_hdr_ddir);
    }

    /* sect */
    file->sec_num = file->pe->sec_num;
    if (file->sec_num >= PE_SECT_MAX)
        return PE_ERR;
    if (spot + (file->sec_num * sizeof(struct pe_hdr_sect)) > blob_len)
        return PE_ERR;
    for (i = 0; i < file->sec_num; i++)
    {
        file->sec[i] = (struct pe_hdr_sect *)&blob[spot];
        spot += sizeof(struct pe_hdr_sect);
    }

    /* act */
    /* TODO: do we want to validate the ACT fields (rev,type) ? */
    if (file->ddir_num >= (PE_DDIR_ACT + 1))
    {
        if (file->ddir[PE_DDIR_ACT]->addr + file->ddir[PE_DDIR_ACT]->len > blob_len)
            return PE_ERR;
        file->act = (struct pe_oth_act *)&blob[file->ddir[PE_DDIR_ACT]->addr];
    }
    else
        file->act = NULL;

    return PE_OK;
}
