/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014 Nahanni Systems Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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

#include <sys/types.h>
#include <sys/queue.h>

#include <sys/param.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "usb_emul.h"

#define MAXUSBBUSES 4
#define MAXSLOTS    8

int max_usb_slot = 1;

SET_DECLARE(usb_emu_set, struct usb_devemu);

void
usb_print_supported_devices(void)
{
	struct usb_devemu **pdpp, *pdp;

	SET_FOREACH(pdpp, usb_emu_set)
	{
		pdp = *pdpp;
		printf("%s\n", pdp->ue_emu);
	}
}

struct usb_devemu *
usb_emu_finddev(const char *name)
{
	struct usb_devemu **udpp, *udp;

	SET_FOREACH(udpp, usb_emu_set)
	{
		udp = *udpp;
		if (!strcmp(udp->ue_emu, name))
			return (udp);
	}

	return (NULL);
}

static void
usb_parse_slot_usage(char *aopt)
{
	EPRINTLN("Invalid USB slot info field \"%s\"", aopt);
}

/*
 * USB device configuration is stored in MIBs that encode the device's
 * location:
 *
 * usb.<slot>
 */
int
usb_parse_device(char *opt)
{
	char node_name[sizeof("usb.XX.XX")];
	struct usb_devemu *pde;
	char *emul, *config, *str, *cp;
	int error, bnum, snum;
	nvlist_t *nvl;

	error = -1;
	str = strdup(opt);
	bnum = 0;

	emul = config = NULL;
	if (isdigit(str[0]) && (cp = strchr(str, ',')) != NULL) {
		*cp = '\0';
		emul = cp + 1;
		if ((cp = strchr(emul, ',')) != NULL) {
			*cp = '\0';
			config = cp + 1;
		}

		/* <bus>:<slot> */
		if (sscanf(str, "%d:%d", &bnum, &snum) != 2) {
			bnum = 0;
			/* <slot> */
			if (sscanf(str, "%d", &snum) != 1)
				snum = max_usb_slot++;
		}
	} else if ((cp = strchr(str, ',')) != NULL) {
		*cp = '\0';
		emul = str;
		config = cp + 1;
		snum = max_usb_slot++;
	} else {
		emul = str;
		snum = max_usb_slot++;
	}

	if (bnum < 0 || bnum >= MAXUSBBUSES || snum < 1 || snum >= MAXSLOTS) {
		usb_parse_slot_usage(opt);
		goto done;
	}
	max_usb_slot = MAX(snum + 1, max_usb_slot);

	pde = usb_emu_finddev(emul);
	if (pde == NULL) {
		EPRINTLN("usb slot %d:%d: unknown device \"%s\"", bnum, snum,
		    emul);
		goto done;
	}

	snprintf(node_name, sizeof(node_name), "usb.%d.%d", bnum, snum);
	nvl = find_config_node(node_name);
	if (nvl != NULL) {
		EPRINTLN("usb slot %d:%d already occupied!", bnum, snum);
		goto done;
	}
	nvl = create_config_node(node_name);
	set_config_value_node(nvl, "device", pde->ue_emu);

	error = pci_parse_legacy_config(nvl, config);
done:
	free(str);
	return (error);
}

struct usb_data_xfer_block *
usb_data_xfer_append(struct usb_data_xfer *xfer, void *buf, int blen,
    void *hci_data, int ccs)
{
	struct usb_data_xfer_block *xb;

	if (xfer->ndata >= USB_MAX_XFER_BLOCKS)
		return (NULL);

	xb = &xfer->data[xfer->tail];
	xb->buf = buf;
	xb->blen = blen;
	xb->hci_data = hci_data;
	xb->ccs = ccs;
	xb->processed = 0;
	xb->bdone = 0;
	xfer->ndata++;
	xfer->tail = (xfer->tail + 1) % USB_MAX_XFER_BLOCKS;
	return (xb);
}
