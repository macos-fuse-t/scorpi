/*
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_VMM_INSTRUCTION_EMUL_H_
#define	_VMM_INSTRUCTION_EMUL_H_

/*
 * Callback functions to read and write memory regions.
 */
typedef int (*mem_region_read_t)(struct vcpu *vcpu, uint64_t gpa,
				 uint64_t *rval, int rsize, void *arg);
typedef int (*mem_region_write_t)(struct vcpu *vcpu, uint64_t gpa,
				  uint64_t wval, int wsize, void *arg);

/*
 * Callback functions to read and write registers.
 */
typedef int (*reg_read_t)(struct vcpu *vcpu, uint64_t *rval, void *arg);
typedef int (*reg_write_t)(struct vcpu *vcpu, uint64_t wval, void *arg);

/*
 * Emulate the decoded 'vie' instruction when it contains a memory operation.
 *
 * The callbacks 'mrr' and 'mrw' emulate reads and writes to the memory region
 * containing 'gpa'. 'mrarg' is an opaque argument that is passed into the
 * callback functions.
 *
 * 'void *vm' should be 'struct vm *' when called from kernel context and
 * 'struct vmctx *' when called from user context.
 *
 */
int vmm_emulate_instruction(struct vcpu *vcpu, uint64_t gpa, struct vie *vie,
    struct vm_guest_paging *paging, mem_region_read_t mrr,
    mem_region_write_t mrw, void *mrarg);

/*
 * Emulate the decoded 'vre' instruction when it contains a register access.
 *
 * The callbacks 'regread' and 'regwrite' emulate reads and writes to the
 * register from 'vie'. 'regarg' is an opaque argument that is passed into the
 * callback functions.
 *
 * 'void *vm' should be 'struct vm *' when called from kernel context and
 * 'struct vmctx *' when called from user context.
 *
 */
int vmm_emulate_register(struct vcpu *vcpu, struct vre *vre, reg_read_t regread,
    reg_write_t regwrite, void *regarg);

#endif	/* _VMM_INSTRUCTION_EMUL_H_ */
