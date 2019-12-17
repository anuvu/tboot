/*
 * ASN.1/DER functions
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
#include <printk.h>

#include "asn1.h"

/* id/tag names */
/* NOTE: must have a definition for everything within ASN1_TAG_MASK */
const char *asn1_tag_names[] =
{
    [0x00] = "<UNDEF_00>",
    [0x01] = "BOOLEAN",
    [0x02] = "INTEGER",
    [0x03] = "BITSTR",
    [0x04] = "OCTSTR",
    [0x05] = "NULL",
    [0x06] = "OID",
    [0x07] = "OBJDESC",
    [0x08] = "INSTANCE",
    [0x09] = "REAL",
    [0x0a] = "ENUMERATED",
    [0x0b] = "EMBEDPDV",
    [0x0c] = "UTF8STR",
    [0x0d] = "RELOID",
    [0x0e] = "<UNDEF_0E>",
    [0x0f] = "<UNDEF_0F>",
    [0x10] = "SEQUENCE",
    [0x11] = "SET",
    [0x12] = "NUMSTR",
    [0x13] = "PRINTSTR",
    [0x14] = "T61STR",
    [0x15] = "VTEXSTR",
    [0x16] = "IA5STR",
    [0x17] = "UTCTIME",
    [0x18] = "GENTIME",
    [0x19] = "GRAPHSTR",
    [0x1a] = "ISO64STR",
    [0x1b] = "GENSTR",
    [0x1c] = "UNIVSTR",
    [0x1d] = "CHARSTR",
    [0x1e] = "BMPSTR",
    [0x1f] = "<UNDEF_1F>"
};

/*
 * helpers
 */

static int32_t _asn1_blob_rem(const struct asn1_hndl *hndl)
{
    return (hndl->blob_len - hndl->offset_cur + 1);
}

static int32_t _asn1_eof(const struct asn1_hndl *hndl)
{
    if (_asn1_blob_rem(hndl) <= 0)
        return ASN1_EOF;
    return ASN1_OK;
}

/*
 * identifier
 */

enum asn1_class asn1_id_class(uint8_t der)
{
    return (der & 0xc0);
}

static int32_t _asn1_id_tag_low(uint8_t der, uint32_t *consumed)
{
    if (consumed)
        *consumed = 1;
    return (der & 0x3f);
}

static int32_t _asn1_id_tag_high(unsigned char *der, uint32_t der_len,
                                 uint32_t *consumed)
{
    int32_t id;
    uint32_t len = 0;
    unsigned int i;

    /* NOTE: we assume all our id values can fit in a 32-bit integer */

    /* sanity checks */
    if (!der || der_len < 1)
        return ASN1_ERR;
    if ((der[0] & 0x1f) != 0x1f)
        return ASN1_ERR;

    /* calculate the number using base 128 */
    i = 0;
    id = 0;
    do
    {
        i++;
        id <<= 7;
        id |= (der[i] & 0x7f);
        len++;
    }
    while ((der[i] & 0x80) && ((i + 1) < der_len));

    if (consumed)
        *consumed = len;
    return id;
}

int32_t asn1_id_tag(unsigned char *der, uint32_t der_len, uint32_t *consumed)
{
    int32_t tag;
    uint32_t len = 0;

    if (!der || der_len < 1)
        return ASN1_ERR;

    if ((der[0] & 0x1f) == 0x1f)
        tag = _asn1_id_tag_high(der, der_len, &len);
    else
        tag = _asn1_id_tag_low(der[0], &len);

    if (consumed)
        *consumed = len;
    return tag;
}

bool asn1_id_primitive(uint32_t tag)
{
    return !(tag & 0x20);
}

bool asn1_id_constructed(uint32_t tag)
{
    return (tag & 0x20);
}

const char *asn1_id_name(uint32_t tag)
{
    return asn1_tag_names[tag & ASN1_TAG_MASK];
}

/*
 * length
 */

static int32_t _asn1_len_short(uint8_t der, uint32_t *consumed)
{
    /* sanity checks */
    if (der & 0x80)
        return ASN1_ERR;

    if (consumed)
        *consumed = 1;
    return (der & 0x7f);
}

static int32_t _asn1_len_long(unsigned char *der, uint32_t der_len, uint32_t *consumed)
{
    int32_t len = 0;
    uint32_t len_hdr = 1;
    unsigned int i, octets;

    /* NOTE: we assume all our length values can fit in a 32-bit integer */

    /* sanity checks */
    if (!der)
        return ASN1_ERR;
    if (!(der[0] & 0x80))
        return ASN1_ERR;
    octets = der[0] & 0x7f;
    if ((octets + 1) > der_len)
        return ASN1_ERR;

    /* calculate the length using base 256 */
    for (i = 0; i < octets; i++)
    {
        len <<= 8;
        len |= der[i + 1];
        len_hdr++;
    }

    if (consumed)
        *consumed = len_hdr;
    return len;
}

int32_t asn1_len(unsigned char *der, uint32_t der_len, uint32_t *consumed)
{
    if (!der && der_len < 1)
        return ASN1_ERR;

    if (der[0] & 0x80)
        return _asn1_len_long(der, der_len, consumed);
    else
        return _asn1_len_short(der[0], consumed);
}

/*
 * content
 */

int asn1_value(struct asn1_hndl *hndl, struct asn1_value *value)
{
    int rc;
    int32_t der_rem, len_tot;
    uint32_t len = 0, len_tmp;
    unsigned char *der;

    if (!hndl || !value)
        return ASN1_ERR;
    der_rem = _asn1_blob_rem(hndl);
    if (der_rem <= 0)
        return ASN1_EOF;

    /* TODO: memset @value here for safety? */

    der = &hndl->blob[hndl->offset_cur];
    value->raw = der;

    /* id */
    rc = asn1_id_tag(der, der_rem, &len_tmp);
    if (rc < 0)
        return rc;
    len += len_tmp;
    value->tag = rc;
    value->tag_raw = der[0];
    der += len_tmp;
    der_rem -= len_tmp;

    /* length */
    rc = asn1_len(der, der_rem, &len_tmp);
    if (rc < 0)
        return rc;
    len += len_tmp;
    value->len_hdr = len;
    value->len_val = rc;
    len_tot = value->len_val + value->len_hdr;
    if (len_tot > der_rem)
        return ASN1_ERR;
    der += len_tmp;
    der_rem -= len_tmp;

    /* content */
    value->value = der;

    /* cache the next value offset */
    if (hndl->offset_nxt <= hndl->offset_cur)
    {
        hndl->offset_nxt_constr = hndl->offset_cur + len_tot;
        if (asn1_id_primitive(value->tag))
            hndl->offset_nxt = hndl->offset_cur + len_tot;
        else
            /* NOTE: constr types only skip the hdr by default */
            hndl->offset_nxt = hndl->offset_cur + value->len_hdr;
    }

    /* depth */
    /* TODO: make sure there are no other reasons for a stack bump */
    switch (value->tag & ASN1_TAG_MASK)
    {
    case tag_seq:
    case tag_set:
        /* stack bump? */
        if (hndl->depth_cur + 1 >= ASN1_STACK_SIZE)
            return ASN1_STACK;
        hndl->depth_cur++;
        value->depth = hndl->depth_cur;
        hndl->stack[hndl->depth_cur].head = *value;
        hndl->stack[hndl->depth_cur].offset_end = hndl->offset_cur + len_tot;
        break;
    default:
        value->depth = hndl->depth_cur;
        break;
    }

    return ASN1_OK;
}

int asn1_value_next(struct asn1_hndl *hndl, struct asn1_value *value)
{
    int rc;

    rc = asn1_value(hndl, value);
    if (rc != ASN1_OK)
        return rc;
    return asn1_next(hndl);
}

int asn1_obj(struct asn1_value *value, uint32_t component)
{
    int32_t rc;
    unsigned char *val = value->value;
    uint32_t val_len = value->len_val;
    uint32_t i = 0;
    uint32_t spot = 0;

    /* TODO: this assumes all the components can fit in a int32_t */

    while (i < val_len)
    {
        switch (spot)
        {
        /* first octet: 40 * value1 + value2 */
        case 0:
            rc = val[i] / 40;
            break;
        case 1:
            rc = val[i] % 40;
            i++;
            break;
        /* nth octet: base 128, 8th bit 1, last octet 8th bit 0 */
        default:
            /* calculate the number using base 128 */
            rc = 0;
            do
            {
                rc <<= 7;
                rc |= (val[i] & 0x7f);
                i++;
            }
            while ((val[i - 1] & 0x80) && (i < val_len));
            break;
        }
        if (spot++ == component)
            return rc;
    }

    /* TODO: rework returning values/errors */
    return ASN1_EOF;
}

/*
 * misc
 */

static void _asn1_next_raw(struct asn1_hndl *hndl, uint32_t next)
{
    /* update the current offset pointer */
    hndl->offset_cur = next;

    /* stack drop? */
    while (hndl->depth_cur > 0)
    {
        if (hndl->offset_cur >= hndl->stack[hndl->depth_cur].offset_end)
            hndl->depth_cur--;
        else
            break;
    }
}

int asn1_next(struct asn1_hndl *hndl)
{
    /* NOTE: if a constructed type, only skip past the header */

    if (!hndl)
        return ASN1_ERR;
    if (_asn1_eof(hndl))
        return ASN1_EOF;

    /* we cached the next value in asn1_value() */
    _asn1_next_raw(hndl, hndl->offset_nxt);

    return ASN1_OK;
}

int asn1_next_constr(struct asn1_hndl *hndl)
{
    /* NOTE: if a constructed type, skip the entire type */

    if (!hndl)
        return ASN1_ERR;
    if (_asn1_eof(hndl))
        return ASN1_EOF;

    /* we cached the next value in asn1_value() */
    _asn1_next_raw(hndl, hndl->offset_nxt_constr);

    return ASN1_OK;
}

int asn1_skip(struct asn1_hndl *hndl)
{
    struct asn1_value dummy;
    return asn1_value_next(hndl, &dummy);
}

int asn1_offset(struct asn1_hndl *hndl)
{
    if (!hndl)
        return ASN1_ERR;

    return hndl->offset_cur;
}

int asn1_load(unsigned char *blob, uint32_t blob_len,
              struct asn1_hndl *hndl)
{
    unsigned int i;

    if (!hndl || !blob || blob_len == 0)
        return ASN1_ERR;

    /* TODO: memset @hndl here for safety? */

    hndl->blob = blob;
    hndl->blob_len = blob_len;

    for (i = 0; i < ASN1_STACK_SIZE; i++)
        hndl->stack[i].depth = i;

    hndl->offset_cur = 0;
    hndl->depth_cur = 0;
    hndl->offset_nxt = 0;
    hndl->offset_nxt_constr = 0;

    return ASN1_OK;
}

/*
 * blob
 */

void asn1_blob_set(struct asn1_blob *blob, struct asn1_value *value)
{
    if (!blob || !value)
        return;

    blob->data = value->value;
    blob->len = value->len_val;
}

int asn1_blob_cmp(struct asn1_blob *a, struct asn1_blob *b)
{
    if (!a || !b)
        return -1;

    if (a->len != b->len)
        return -1;
    return tb_memcmp(a->data, b->data, a->len);
}

int asn1_blob_memcmp(struct asn1_blob *blob, void *data, uint32_t len)
{
    if (!blob || !data || len == 0)
        return -1;

    if (len != blob->len)
        return -1;
    return tb_memcmp(blob->data, data, len);
}

int asn1_blob_strcmp(struct asn1_blob *blob, char *string)
{
    if (!blob || !string)
        return -1;

    return asn1_blob_memcmp(blob, (unsigned char *)string, tb_strlen(string));
}

void asn1_blob_printstr(struct asn1_blob *blob)
{
    char buffer[161];

    if (!blob || blob->len == 0 || !blob->data)
    {
        printk(TBOOT_INFO"(NULL)");
        return;
    }

    if (blob->len >= sizeof(buffer))
    {
        printk(TBOOT_INFO"(ERROR)");
        return;
    }

    tb_strncpy(buffer, (char *)blob->data, blob->len);
    buffer[blob->len] = '\0';
    printk(TBOOT_INFO"%s", buffer);
}

void asn1_blob_printhex(struct asn1_blob *blob)
{
    unsigned int iter;

    if (!blob || blob->len == 0 || !blob->data)
    {
        printk(TBOOT_INFO"(NULL)");
        return;
    }

    for (iter = 0; iter < blob->len; iter++)
        printk(TBOOT_INFO"%02x", blob->data[iter]);
}
