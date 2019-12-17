/*
 * PE/COFF functions
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

#ifndef __PECOFF_H
#define __PECOFF_H

#include <types.h>

#include "error.h"
#include "pkcs7.h"

#define PE_OK                   ERROR_OK
#define PE_ERR                  ERROR_ERR
#define PE_EINVAL               ERROR_EINVAL
#define PE_CRYPTERR             ERROR_CRYPTERR
#define PE_CRYPTFAIL            ERROR_CRYPTFAIL

/*
 * MZ header
 */
struct pe_hdr_mz
{
    unsigned char magic[2];     /* 0x4d5a "MZ" */
    uint16_t blk_lst_len;
    uint16_t blk_num;
    uint16_t rloc_num;
    uint16_t hdr_len;
    uint16_t hdr_xtra_min;
    uint16_t hdr_xtra_max;
    uint16_t ss;
    uint16_t sp;
    uint16_t cksum;
    uint16_t ip;
    uint16_t cs;
    uint16_t rloc_off;
    uint16_t ovrly_num;
    uint16_t reserved_a[4];
    uint16_t oem_id;
    uint16_t oem_info;
    uint16_t reserved_b[10];
    uint16_t pe_off;            /* all we care about? */
};

/*
 * PE header
 */
struct pe_hdr_pe
{
    unsigned char magic[4];     /* 0x50450000 "PE\0\0" */
    uint16_t machine;           /* 0x8664 for x86_64 */
    uint16_t sec_num;
    uint32_t timestamp;
    uint32_t symtbl_off;        /* should be 0 */
    uint32_t sym_num;           /* should be 0 */
    uint16_t opt_len;
    uint16_t flags;
};

/*
 * PE optional header
 *
 * NOTE: this is the PE32+ definition
 */
struct pe_hdr_peopt
{
    uint16_t magic;             /* 0x020b for PE32+ */
    uint8_t link_maj;
    uint8_t link_min;
    uint32_t text_len;
    uint32_t data_len;
    uint32_t bss_len;
    uint32_t entry_addr;
    uint32_t base_addr;
    /* NOTE: PE32 has a uint32_t "BaseOfData" here, not present in PE32+ */
    /* NOTE: we need the "windows specific" info for the hash calculation */
    /* NOTE: everything uses the PE32+ definitions */
    uint64_t mem_base;
    uint32_t sec_align;
    uint32_t file_align;
    uint16_t osver_maj;
    uint16_t osver_min;
    uint16_t imgver_maj;
    uint16_t imgver_min;
    uint16_t sysver_maj;
    uint16_t sysver_min;
    uint32_t ver_win32;         /* must be 0 */
    uint32_t img_len;
    uint32_t hdr_len;
    uint32_t chksum;
    uint16_t subsys;
    uint16_t dll_chars;
    uint64_t stackrsv_len;
    uint64_t stackcmt_len;
    uint64_t heaprsv_len;
    uint64_t heapcmt_len;
    uint32_t loader_flags;      /* must be 0 */
    uint32_t ddir_num;
};

/*
 * PE data directory header
 */
/* TODO: define magic numbers for other ddirs */
#define PE_DDIR_ACT         4
struct pe_hdr_ddir
{
    uint32_t addr;
    uint32_t len;
};

/*
 * PE section header
 */
struct pe_hdr_sect
{
    char name[8];
    uint32_t virt_len;
    uint32_t virt_addr;
    uint32_t data_len;
    uint32_t data_addr;
    uint32_t reloc_addr;
    uint32_t lnum_addr;
    uint16_t reloc_num;
    uint16_t lnum_num;
    uint32_t flags;
};

/*
 * PE attribute certificate table
 */
struct pe_oth_act
{
    uint32_t len;
    uint16_t rev;               /* we understand revision 2 */
    uint16_t type;              /* must be 2 for authenticode */
    unsigned char cert[0];
};

/*
 * PE/COFF file
 */
/* NOTE: the header limits are not based on anything meaningful */
#define PE_DDIR_MAX         32
#define PE_SECT_MAX         32
struct pe_file
{
    /* raw file pointers */
    unsigned char *raw_head;
    uint32_t raw_len;

    /* main pe/coff file components */
    struct pe_hdr_mz *mz;
    struct pe_hdr_pe *pe;
    struct pe_hdr_peopt *opt;
    struct pe_hdr_ddir *ddir[PE_DDIR_MAX];
    uint32_t ddir_num;
    struct pe_hdr_sect *sec[PE_SECT_MAX];
    uint32_t sec_num;

    /* certificate info */
    struct pe_oth_act *act;

    /* authenticode info */
    struct pkcs7_signeddata pkcs7;
};

int pe_parse(struct pe_file *file, unsigned char *blob, uint32_t blob_len);

int pe_ac_digest_verify(struct pe_file *file);

#endif
