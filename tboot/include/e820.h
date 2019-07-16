/*
 * e820.h: support functions for manipulating the e820 table
 *
 * Copyright (c) 2006-2009, Intel Corporation
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

#ifndef __E820_H__
#define __E820_H__

#ifndef E820_RAM
#define E820_RAM            1
#endif

#ifndef E820_RESERVED
#define E820_RESERVED       2
#endif

#ifndef E820_ACPI
#define E820_ACPI           3
#endif

#ifndef E820_NVS
#define E820_NVS            4
#endif

#ifndef E820_UNUSABLE
#define E820_UNUSABLE       5
#endif

/* these are only used by e820_check_region() */
#define E820_MIXED          ((uint32_t)-1 - 1)
#define E820_GAP            ((uint32_t)-1)

#define E820MAX             128

typedef struct __packed {
    uint64_t addr;    /* start of memory segment */
    uint64_t size;    /* size of memory segment */
    uint32_t type;    /* type of memory segment */
} e820entry_t;

typedef struct {
	uint32_t type;
	uint32_t pad;
	uint64_t phys_addr;
	uint64_t virt_addr;
	uint64_t num_pages;
	uint64_t attribute;
} efi_memory_desc_t;

extern memory_map_t *get_e820_copy(void);
extern unsigned int get_nr_map(void);
extern bool copy_e820_map(loader_ctx *lctx);
extern bool e820_protect_region(uint64_t addr, uint64_t size, uint32_t type);
extern bool e820_reserve_ram(uint64_t base, uint64_t length);
extern void print_e820_map(void);
extern uint32_t e820_check_region(uint64_t base, uint64_t length);
extern bool get_ram_ranges(uint64_t *min_lo_ram, uint64_t *max_lo_ram,
                           uint64_t *min_hi_ram, uint64_t *max_hi_ram);
extern void get_highest_sized_ram(uint64_t size, uint64_t limit,
                                  uint64_t *ram_base, uint64_t *ram_size);

/*
 * Memory map descriptor:
 */

/* Memory types: */
#define EFI_RESERVED_TYPE		 0
#define EFI_LOADER_CODE			 1
#define EFI_LOADER_DATA			 2
#define EFI_BOOT_SERVICES_CODE		 3
#define EFI_BOOT_SERVICES_DATA		 4
#define EFI_RUNTIME_SERVICES_CODE	 5
#define EFI_RUNTIME_SERVICES_DATA	 6
#define EFI_CONVENTIONAL_MEMORY		 7
#define EFI_UNUSABLE_MEMORY		 8
#define EFI_ACPI_RECLAIM_MEMORY		 9
#define EFI_ACPI_MEMORY_NVS		10
#define EFI_MEMORY_MAPPED_IO		11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE	12
#define EFI_PAL_CODE			13
#define EFI_MAX_MEMORY_TYPE		14

/* Attribute values: */
#define EFI_MEMORY_UC		((u64)0x0000000000000001ULL)	/* uncached */
#define EFI_MEMORY_WC		((u64)0x0000000000000002ULL)	/* write-coalescing */
#define EFI_MEMORY_WT		((u64)0x0000000000000004ULL)	/* write-through */
#define EFI_MEMORY_WB		((u64)0x0000000000000008ULL)	/* write-back */
#define EFI_MEMORY_WP		((u64)0x0000000000001000ULL)	/* write-protect */
#define EFI_MEMORY_RP		((u64)0x0000000000002000ULL)	/* read-protect */
#define EFI_MEMORY_XP		((u64)0x0000000000004000ULL)	/* execute-protect */
#define EFI_MEMORY_RUNTIME	((u64)0x8000000000000000ULL)	/* range requires runtime mapping */
#define EFI_MEMORY_DESCRIPTOR_VERSION	1

#define EFI_PAGE_SHIFT		12

#endif    /* __E820_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
