/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Nahanni Systems, Inc.
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

#include <sys/types.h>
#include <sys/mman.h>

#include <vmm.h>
// #include <machine/vmm_snapshot.h>
#include <vmmapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include <sys/posix_shm.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "bhyvegc.h"
#include "bhyverun.h"
#include "config.h"
#include "console.h"
#include "debug.h"
#include "pci_emul.h"
#include "rfb.h"
#ifdef __amd64__
#include "amd64/vga.h"
#endif
#include <zlib.h>
#include "cnc.h"
#include "virtio_gpu.h"

/*
 * bhyve Framebuffer device emulation.
 * BAR0 points to the current mode information.
 * BAR1 is the 32-bit framebuffer address.
 *
 *  -s <b>,fbuf,wait,vga=on|io|off,rfb=<ip>:port,w=width,h=height
 */

static int fbuf_debug = 0;
#define DEBUG_INFO    1
#define DEBUG_VERBOSE 4
#define DPRINTF(level, params)   \
	if (level <= fbuf_debug) \
	PRINTLN params

#define KB	     (1024UL)
#define MB	     (1024 * 1024UL)

#define DMEMSZ	     128

#define FB_SIZE	     (128 * MB)

#define COLS_MAX     3840
#define ROWS_MAX     2160

#define COLS_DEFAULT 1024
#define ROWS_DEFAULT 768

#define COLS_MIN     640
#define ROWS_MIN     480

struct pci_fbuf_softc {
	struct pci_devinst *fsc_pi;
	struct {
		uint32_t fbsize;
		uint16_t width;
		uint16_t height;
		uint16_t depth;
		uint16_t refreshrate;
		uint8_t reserved[116];
	} __packed memregs;

	/* rfb server */
	char *rfb_host;
	char *rfb_password;
	int rfb_port;
	int rfb_wait;
	int vga_enabled;
	int vga_full;

	uint32_t fbaddr;
	char *fb_base;
	uint16_t gc_width;
	uint16_t gc_height;
	void *vgasc;
	struct bhyvegc_image *gc_image;

	char shm_name[sizeof(uuid_string_t) + 1];
	int shm_fd;
};

extern uuid_t vm_uuid;

static struct pci_fbuf_softc *fbuf_sc;

#define PCI_FBUF_MSI_MSGS 4

static void pci_fbuf_render(void *arg);

static void
pci_fbuf_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct pci_fbuf_softc *sc;
	uint8_t *p;

	assert(baridx == 0);

	sc = pi->pi_arg;

	DPRINTF(DEBUG_VERBOSE,
	    ("fbuf wr: offset 0x%llx, size: %d, value: 0x%llx", offset, size,
		value));

	if (offset + size > DMEMSZ) {
		printf("fbuf: write too large, offset %lld size %d\n", offset,
		    size);
		return;
	}

	p = (uint8_t *)&sc->memregs + offset;

	switch (size) {
	case 1:
		*p = value;
		break;
	case 2:
		*(uint16_t *)p = value;
		break;
	case 4:
		*(uint32_t *)p = value;
		break;
	case 8:
		*(uint64_t *)p = value;
		break;
	default:
		printf("fbuf: write unknown size %d\n", size);
		break;
	}

	/*f (!sc->gc_image->vgamode && sc->memregs.width == 0 &&
	    sc->memregs.height == 0) {
		DPRINTF(DEBUG_INFO, ("switching to VGA mode"));
		sc->gc_image->vgamode = 1;
		sc->gc_width = 0;
		sc->gc_height = 0;
	} else if (sc->gc_image->vgamode && sc->memregs.width != 0 &&
	    sc->memregs.height != 0) {
		DPRINTF(DEBUG_INFO, ("switching to VESA mode"));
		sc->gc_image->vgamode = 0;
	}*/
}

static uint64_t
pci_fbuf_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct pci_fbuf_softc *sc;
	uint8_t *p;
	uint64_t value;

	assert(baridx == 0);

	sc = pi->pi_arg;

	if (offset + size > DMEMSZ) {
		printf("fbuf: read too large, offset %llu size %d\n", offset,
		    size);
		return (0);
	}

	p = (uint8_t *)&sc->memregs + offset;
	value = 0;
	switch (size) {
	case 1:
		value = *p;
		break;
	case 2:
		value = *(uint16_t *)p;
		break;
	case 4:
		value = *(uint32_t *)p;
		break;
	case 8:
		value = *(uint64_t *)p;
		break;
	default:
		printf("fbuf: read unknown size %d\n", size);
		break;
	}

	DPRINTF(DEBUG_VERBOSE,
	    ("fbuf rd: offset 0x%llx, size: %d, value: 0x%llx", offset, size,
		value));

	return (value);
}

int once = 0;

static void
pci_fbuf_baraddr(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address)
{
	struct pci_fbuf_softc *sc;
	int prot;

	if (baridx != 1)
		return;

	sc = pi->pi_arg;
	if (!enabled) {
		/*if (vm_munmap_memseg(pi->pi_vmctx, sc->fbaddr, FB_SIZE) != 0)
			EPRINTLN("pci_fbuf: munmap_memseg failed");*/
		sc->fbaddr = 0;
	} else {
		if (once) {
			return;
		}
		once++;

		// frambuffer resides in shared memory
		sc->shm_name[0] = '/';
		uuid_unparse(vm_uuid, sc->shm_name + 1);
		if (sizeof(sc->shm_name) > PSHMNAMLEN) {
			sc->shm_name[PSHMNAMLEN] = 0;
		}

		sc->shm_fd = shm_open(sc->shm_name, O_CREAT | O_RDWR,
		    S_IRUSR | S_IWUSR);
		if (sc->shm_fd == -1) {
			EPRINTLN("shm_open %s", sc->shm_name);
			exit(-1);
		}

		// Resize the shared memory
		if (ftruncate(sc->shm_fd, FB_SIZE) == -1) {
			EPRINTLN("ftruncate");
			shm_unlink(sc->shm_name);
			exit(-1);
		}

		sc->fb_base = mmap(NULL, FB_SIZE, PROT_READ | PROT_WRITE,
		    MAP_SHARED, sc->shm_fd, 0);
		if (sc->fb_base == MAP_FAILED) {
			EPRINTLN("mmap");
			shm_unlink(sc->shm_name);
			exit(1);
		}

		prot = PROT_READ | PROT_WRITE | PROT_DONT_ALLOCATE;
		if (vm_setup_memory_segment(pi->pi_vmctx, address, FB_SIZE,
			prot, (uintptr_t *)&sc->fb_base)) {
			EPRINTLN("pci_fbuf: vm_setup_memory_segment() failed");
		}
		sc->fbaddr = address;

		console_set_scanout(true, sc->memregs.width, sc->memregs.height,
		    sc->memregs.width * 4, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
		    sc->shm_name, FB_SIZE, true);
		console_fb_register(pci_fbuf_render, sc);
		memset((void *)sc->fb_base, 0, FB_SIZE);
	}
}

static int
pci_fbuf_parse_config(struct pci_fbuf_softc *sc, nvlist_t *nvl)
{
	const char *value;
	char *cp;

	sc->rfb_wait = get_config_bool_node_default(nvl, "wait", false);

	/* Prefer "rfb" to "tcp". */
	value = get_config_value_node(nvl, "rfb");
	if (value == NULL)
		value = get_config_value_node(nvl, "tcp");
	if (value != NULL) {
		/*
		 * IPv4 -- host-ip:port
		 * IPv6 -- [host-ip%zone]:port
		 * XXX for now port is mandatory for IPv4.
		 */
		if (value[0] == '[') {
			cp = strchr(value + 1, ']');
			if (cp == NULL || cp == value + 1) {
				EPRINTLN("fbuf: Invalid IPv6 address: \"%s\"",
				    value);
				return (-1);
			}
			sc->rfb_host = strndup(value + 1, cp - (value + 1));
			cp++;
			if (*cp == ':') {
				cp++;
				if (*cp == '\0') {
					EPRINTLN(
					    "fbuf: Missing port number: \"%s\"",
					    value);
					return (-1);
				}
				sc->rfb_port = atoi(cp);
			} else if (*cp != '\0') {
				EPRINTLN("fbuf: Invalid IPv6 address: \"%s\"",
				    value);
				return (-1);
			}
		} else {
			cp = strchr(value, ':');
			if (cp == NULL) {
				sc->rfb_port = atoi(value);
			} else {
				sc->rfb_host = strndup(value, cp - value);
				cp++;
				if (*cp == '\0') {
					EPRINTLN(
					    "fbuf: Missing port number: \"%s\"",
					    value);
					return (-1);
				}
				sc->rfb_port = atoi(cp);
			}
		}
	}

	value = get_config_value_node(nvl, "vga");
	if (value != NULL) {
		if (strcmp(value, "off") == 0) {
			sc->vga_enabled = 0;
		} else if (strcmp(value, "io") == 0) {
			sc->vga_enabled = 1;
			sc->vga_full = 0;
		} else if (strcmp(value, "on") == 0) {
			sc->vga_enabled = 1;
			sc->vga_full = 1;
		} else {
			EPRINTLN("fbuf: Invalid vga setting: \"%s\"", value);
			return (-1);
		}
	}

	value = get_config_value_node(nvl, "w");
	if (value != NULL)
		sc->memregs.width = strtol(value, NULL, 10);

	value = get_config_value_node(nvl, "h");
	if (value != NULL)
		sc->memregs.height = strtol(value, NULL, 10);

	if (sc->memregs.width > COLS_MAX || sc->memregs.height > ROWS_MAX) {
		EPRINTLN("fbuf: max resolution is %ux%u", COLS_MAX, ROWS_MAX);
		return (-1);
	}
	if (sc->memregs.width < COLS_MIN || sc->memregs.height < ROWS_MIN) {
		EPRINTLN("fbuf: minimum resolution is %ux%u", COLS_MIN,
		    ROWS_MIN);
		return (-1);
	}

	value = get_config_value_node(nvl, "password");
	if (value != NULL)
		sc->rfb_password = strdup(value);

	return (0);
}

static void
pci_fbuf_render(void *arg)
{
}

static int
pci_fbuf_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	int error;
	struct pci_fbuf_softc *sc;

	if (fbuf_sc != NULL) {
		EPRINTLN("Only one frame buffer device is allowed.");
		return (-1);
	}

	sc = calloc(1, sizeof(struct pci_fbuf_softc));

	pi->pi_arg = sc;

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x65F1);
	pci_set_cfgdata16(pi, PCIR_VENDOR, 0xFB5D);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_DISPLAY);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_DISPLAY_VGA);

	error = pci_emul_alloc_bar(pi, 0, PCIBAR_MEM32, DMEMSZ);
	assert(error == 0);

	error = pci_emul_alloc_bar(pi, 1, PCIBAR_MEM32, FB_SIZE);
	assert(error == 0);

	error = pci_emul_add_msicap(pi, PCI_FBUF_MSI_MSGS);
	assert(error == 0);

	sc->fbaddr = pi->pi_bar[1].addr;

	sc->memregs.fbsize = FB_SIZE;
	sc->memregs.width = COLS_DEFAULT;
	sc->memregs.height = ROWS_DEFAULT;
	sc->memregs.depth = 32;

	sc->vga_enabled = 1;
	sc->vga_full = 0;

	sc->fsc_pi = pi;

	error = pci_fbuf_parse_config(sc, nvl);
	if (error != 0)
		goto done;

	/* XXX until VGA rendering is enabled */
	if (sc->vga_full != 0) {
		EPRINTLN("pci_fbuf: VGA rendering not enabled");
		goto done;
	}

	DPRINTF(DEBUG_INFO,
	    ("fbuf frame buffer base: %p [sz %lu]", sc->fb_base, FB_SIZE));

	fbuf_sc = sc;

	// error = rfb_init(sc->rfb_host, sc->rfb_port, sc->rfb_wait,
	// sc->rfb_password);
done:
	if (error)
		free(sc);

	return (error);
}

#ifdef BHYVE_SNAPSHOT
static int
pci_fbuf_snapshot(struct vm_snapshot_meta *meta)
{
	int ret;

	SNAPSHOT_BUF_OR_LEAVE(fbuf_sc->fb_base, FB_SIZE, meta, ret, err);

err:
	return (ret);
}
#endif

static const struct pci_devemu pci_fbuf = {
	.pe_emu = "fbuf",
	.pe_init = pci_fbuf_init,
	.pe_barwrite = pci_fbuf_write,
	.pe_barread = pci_fbuf_read,
	.pe_baraddr = pci_fbuf_baraddr,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = pci_fbuf_snapshot,
#endif
};
PCI_EMUL_SET(pci_fbuf);
