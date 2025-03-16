/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Alex Fishman <alex@fuse-t.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/mman.h>
#include <Hypervisor/Hypervisor.h>
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"
#include "vmm_instruction_emul.h"
#include "vmmapi.h"
#include "internal.h"

// hypervisor framework implementation
int
vm_assert_irq(struct vmctx *ctx, uint32_t irq)
{
	hv_gic_set_spi(irq, 1);
	return 0;
}

int
vm_deassert_irq(struct vmctx *ctx, uint32_t irq)
{
	hv_gic_set_spi(irq, 0);
	return 0;
}

int
vm_raise_msi(struct vmctx *ctx, uint64_t addr, uint64_t msg, int bus, int slot,
    int func)
{
	// The reason why MSI doesn't work is because OSes use dist_base and
	// GICD_SETSPI_NSR while apple gic expects mmio_base and
	// GICM_SETSPI_NSR. Even when set can be worked around, clear from the
	// OS side doesn't work
#if 0
    if (hv_gic_send_msi(addr, msg) != HV_SUCCESS) {
        EPRINTLN("hv_gic_send_msi() %llx, %llx", addr, msg);
        exit(-1);
    }
#else
	EPRINTLN("Add support for MSI interrupts: addr %llx %llu", addr, msg);
	exit(-1);
#endif
	return 0;
}

int
vm_get_spi_interrupt_range(uint32_t *spi_intid_base, uint32_t *spi_intid_count)
{
	return hv_gic_get_spi_interrupt_range(spi_intid_base,
		   spi_intid_count) == HV_SUCCESS ?
	    0 :
	    -1;
}

int
vm_attach_vgic(struct vmctx *ctx, uint64_t dist_start, size_t dist_size,
    uint64_t redist_start, size_t redist_size, uint64_t mmio_base,
    uint32_t spi_intid_base, uint32_t spi_intid_count)
{
	return init_apple_vgic(ctx, dist_start, dist_size, redist_start,
	    redist_size, mmio_base, spi_intid_base, spi_intid_count);
}

/*
 * Create a device memory segment identified by 'segid'.
 *
 * Returns a pointer to the memory segment on success and MAP_FAILED otherwise.
 */
/*void *
vm_create_devmem(struct vmctx *ctx, int segid, const char *name, size_t len)
{
    return NULL;
}*/

struct vmctx *
vm_openf(const char *name, int flags)
{
	hv_return_t res = hv_vm_create(NULL);
	if (res != HV_SUCCESS) {
		EPRINTLN("failed to create a vm");
		exit(-1);
	}
	struct vmctx *ctx = malloc(sizeof(struct vmctx));
	memset(ctx, 0, sizeof(*ctx));

	return ctx;
}
