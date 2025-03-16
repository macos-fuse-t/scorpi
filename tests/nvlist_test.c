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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nv.h"

void
test_nvlist()
{
	// Create a new nvlist
	nvlist_t *nvl = nvlist_create(0);
	if (nvl == NULL) {
		perror("nvlist_create failed");
		exit(EXIT_FAILURE);
	}

	// Add various types of data to the nvlist
	nvlist_add_string(nvl, "key1", "value1");
	nvlist_add_number(nvl, "key2", 12345);
	nvlist_add_bool(nvl, "key3", true);
	nvlist_add_binary(nvl, "key4", "binarydata", 10);

	// Serialize the nvlist to a buffer
	size_t nvlist_size;
	void *nvlist_buf = nvlist_pack(nvl, &nvlist_size);
	if (nvlist_buf == NULL) {
		perror("nvlist_pack failed");
		nvlist_destroy(nvl);
		exit(EXIT_FAILURE);
	}

	printf("Serialized nvlist size: %zu\n", nvlist_size);

	// Free the original nvlist
	nvlist_destroy(nvl);

	// Deserialize the buffer back into an nvlist
	nvlist_t *unpacked_nvl = nvlist_unpack(nvlist_buf, nvlist_size, 0);
	free(nvlist_buf);
	if (unpacked_nvl == NULL) {
		perror("nvlist_unpack failed");
		exit(EXIT_FAILURE);
	}

	// Access and verify the data
	const char *str_val = nvlist_get_string(unpacked_nvl, "key1");
	printf("key1: %s\n", str_val);

	int64_t num_val = nvlist_get_number(unpacked_nvl, "key2");
	printf("key2: %lld\n", num_val);

	bool bool_val = nvlist_get_bool(unpacked_nvl, "key3");
	printf("key3: %s\n", bool_val ? "true" : "false");

	size_t binary_len;
	const void *binary_data = nvlist_get_binary(unpacked_nvl, "key4",
	    &binary_len);
	printf("key4: binary data length = %zu\n", binary_len);
	for (size_t i = 0; i < binary_len; i++) {
		printf("%02x ", ((unsigned char *)binary_data)[i]);
	}
	printf("\n");

	// Free the unpacked nvlist
	nvlist_destroy(unpacked_nvl);
}

int
main()
{
	printf("Testing FreeBSD nvlist...\n");
	test_nvlist();
	printf("Test completed successfully.\n");
	return 0;
}
