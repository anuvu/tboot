/*
 * Simplistic "heap" allocation functions
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

/* TODO: this code is painfully simple with almost zero protections and no
 *       thought given to managing the "heap" properly and releasing memory */

#include <types.h>
#include <string.h>
#include <printk.h>
#include <heap_alloc.h>

/* NOTE: we don't currently implement any locking, so be careful */
#define HEAP_SIZE			(256 * 1024)
unsigned char heap[HEAP_SIZE];

/* NOTE: we align to a 32-bit/4-byte boundary, and use heap_entry for bufs */
#define ALIGN(x)	(void *)(((uintptr_t)(x) + 3) & (uintptr_t)~0x03)

struct heap_entry
{
    size_t size;
    unsigned char buffer[0];
};

#define PTR_ENTRY(x)	container_of(x, struct heap_entry, buffer)
#define PTR_LEN(x)	PTR_ENTRY(x)->size

unsigned char *heap_top = heap;
unsigned char *heap_limit = &heap[HEAP_SIZE - 1];

void tb_free(__attribute__((unused)) void *ptr)
{
    /* NOTE: we're not even going to try and get this right */
    return;
}

void *tb_malloc(size_t size)
{
    struct heap_entry *new = ALIGN(heap_top);
    unsigned char *new_top;

    /* we don't do zero-length allocations */
    if (size <= 0)
        return NULL;

    /* make sure we are not out of space */
    new_top = (unsigned char *)new + sizeof(struct heap_entry) + size;
    if (new_top > heap_limit) {
        printk(TBOOT_ERR"Error: failed to allocate %ld bytes in tb_malloc()\n",
               size);
        return NULL;
    }

    /* do any setup we need to do for "new" */
    new->size = size;

    /* we're done - bump the heap and return a pointer to the blob */
    heap_top = new_top;
    return new->buffer;
}

void *tb_calloc(size_t nmemb, size_t size)
{
    void *ptr;
    size_t len = nmemb * size;

    ptr = tb_malloc(len);
    if (ptr)
        tb_memset(ptr, 0, len);

    return ptr;
}

void *tb_realloc(void *ptr, size_t size)
{
    void *ptr_new;
    size_t size_cur;

    if (size == 0)
    {
        tb_free(ptr);
        return NULL;
    }

    /* allocate the new blob */
    ptr_new = tb_malloc(size);
    if (!ptr_new || !ptr)
        return ptr_new;

    /* copy the largest size possible */
    size_cur = PTR_LEN(ptr);
    if (!tb_memcpy(ptr_new, ptr, (size_cur < size ? size_cur : size)))
    {
        tb_free(ptr_new);
        return NULL;
    }

    return ptr_new;
}
