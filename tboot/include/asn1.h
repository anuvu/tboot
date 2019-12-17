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

#ifndef __ASN1_H
#define __ASN1_H

#include <types.h>
#include <stdbool.h>

#include "error.h"

#define ASN1_OK             ERROR_OK
#define ASN1_ERR            ERROR_ERR
#define ASN1_EINVAL         ERROR_EINVAL
#define ASN1_STACK          ERROR_STACK
#define ASN1_EOF            ERROR_EOF

#define ASN1_CLASS_MASK     0xc0
enum asn1_class
{
    class_univ      = 0x00,
    class_app       = 0x40,
    class_cont      = 0x80,
    class_priv      = 0xc0,
};

#define ASN1_TAG_MASK       0x1f
enum asn1_tags
{
    tag_bool        = 0x01,
    tag_int         = 0x02,
    tag_bitstr      = 0x03,
    tag_octstr      = 0x04,
    tag_null        = 0x05,
    tag_oid	        = 0x06,
    tag_objdesc     = 0x07,
    tag_instext     = 0x08,
    tag_real        = 0x09,
    tag_enum        = 0x0a,
    tag_embpdv      = 0x0b,
    tag_utf8str     = 0x0c,
    tag_reloid      = 0x0d,
    tag_seq         = 0x10,
    tag_set         = 0x11,
    tag_numstr      = 0x12,
    tag_printstr    = 0x13,
    tag_t61str      = 0x14,
    tag_vtexstr     = 0x15,
    tag_ia5str      = 0x16,
    tag_utctime     = 0x17,
    tag_gentime     = 0x18,
    tag_graphstr    = 0x19,
    tag_iso64str    = 0x1a,
    tag_genstr      = 0x1b,
    tag_univstr     = 0x1c,
    tag_charstr     = 0x1d,
    tag_bmpstr      = 0x1e,
};

struct asn1_blob
{
    unsigned char *data;
    uint32_t len;
};

struct asn1_value
{
    uint32_t depth;
    uint32_t tag;
    uint32_t tag_raw;
    uint32_t len_hdr;
    uint32_t len_val;
    unsigned char *value;
    unsigned char *raw;
};

struct asn1_stack
{
    uint32_t depth;
    struct asn1_value head;
    uint32_t offset_end;
};

/* NOTE: assume a stack depth of 32 is sufficient (?) */
#define ASN1_STACK_SIZE     32
struct asn1_hndl
{
    /* entire asn1 blob */
    unsigned char *blob;
    uint32_t blob_len;

    /* stack */
    /* TODO: do we really need a stack ? (probably not) */
    struct asn1_stack stack[ASN1_STACK_SIZE];
    uint32_t depth_cur;

    /* asn1 value offsets */
    uint32_t offset_cur;
    uint32_t offset_nxt;
    uint32_t offset_nxt_constr;
};

int asn1_load(unsigned char *blob, uint32_t blob_len,
              struct asn1_hndl *hndl);

int asn1_offset(struct asn1_hndl *hndl);

int asn1_value(struct asn1_hndl *hndl, struct asn1_value *value);
int asn1_value_next(struct asn1_hndl *hndl, struct asn1_value *value);
int asn1_next(struct asn1_hndl *hndl);
int asn1_next_constr(struct asn1_hndl *hndl);
int asn1_skip(struct asn1_hndl *hndl);

int asn1_obj(struct asn1_value *value, uint32_t component);

bool asn1_id_primitive(uint32_t tag);
bool asn1_id_constructed(uint32_t tag);
const char *asn1_id_name(uint32_t tag);

void asn1_blob_set(struct asn1_blob *blob, struct asn1_value *value);
int asn1_blob_cmp(struct asn1_blob *a, struct asn1_blob *b);
int asn1_blob_memcmp(struct asn1_blob *blob, void *data, uint32_t len);
int asn1_blob_strcmp(struct asn1_blob *blob, char *string);

void asn1_blob_printstr(struct asn1_blob *blob);
void asn1_blob_printhex(struct asn1_blob *blob);

#endif
