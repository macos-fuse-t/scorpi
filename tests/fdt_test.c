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

#include <assert.h>
#include <libfdt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_DTB_FILE "test.dtb"

const char *
get_test_dtb_path()
{
	const char *path = getenv("TEST_DTB_FILE");
	printf("path: %s\n", path);
	assert(path != NULL && "TEST_DTB_FILE environment variable not set");
	return path;
}

// Utility to load a test DTB file
void *
load_test_dtb_rw()
{
	const char *fdt_path = get_test_dtb_path();
	FILE *fdt_file = fopen(fdt_path, "rb");
	assert(fdt_file != NULL && "Failed to open TEST_DTB_FILE");

	fseek(fdt_file, 0, SEEK_END);
	long fdt_size = ftell(fdt_file);
	rewind(fdt_file);

	// Allocate space for the FDT with extra room for modifications
	long extra_space = 1024; // Allocate an additional 1 KB of space
	void *fdt = malloc(fdt_size + extra_space);
	assert(fdt != NULL);

	fread(fdt, 1, fdt_size, fdt_file);
	fclose(fdt_file);

	// Open the FDT with additional space
	int ret = fdt_open_into(fdt, fdt, fdt_size + extra_space);
	assert(ret == 0 && "Failed to open FDT blob with extra space");

	return fdt;
}

const void *
load_test_dtb()
{
	return load_test_dtb_rw(); // Use same loader but avoid modifying the
				   // FDT
}

// Test: Validate FDT header
void
test_fdt_open_and_check()
{
	printf("Running: test_fdt_open_and_check\n");

	void *fdt = load_test_dtb_rw();
	int ret = fdt_check_header(fdt);
	assert(ret == 0); // 0 indicates valid FDT
	printf("FDT header validation passed.\n");

	free(fdt);
}

// Test: Read a property from FDT
void
test_fdt_get_property()
{
	printf("Running: test_fdt_get_property\n");

	const void *fdt = load_test_dtb();
	const char *node_path = "/chosen";
	const char *property_name = "bootargs";

	int node_offset = fdt_path_offset(fdt, node_path);
	assert(node_offset >= 0);

	int len;
	const char *prop = fdt_getprop(fdt, node_offset, property_name, &len);
	assert(prop != NULL);
	assert(len > 0);

	printf("Property %s: %s\n", property_name, prop);
}

// Test: Add a property to FDT
void
test_fdt_add_property()
{
	printf("Running: test_fdt_add_property\n");

	void *fdt = load_test_dtb_rw();
	const char *node_path = "/test-node";
	const char *property_name = "new-prop2";
	const char *property_value = "test-value2";

	int node_offset = fdt_path_offset(fdt, node_path);
	if (node_offset < 0) {
		node_offset = fdt_add_subnode(fdt, 0, node_path);
		assert(node_offset >= 0);
	}

	int ret = fdt_setprop_string(fdt, node_offset, property_name,
	    property_value);
	assert(ret == 0);

	const char *prop = fdt_getprop(fdt, node_offset, property_name, NULL);
	assert(prop != NULL);
	assert(strcmp(prop, property_value) == 0);

	printf("Added property %s: %s\n", property_name, prop);

	free(fdt);
}

// Test: Delete a property from FDT
void
test_fdt_del_property()
{
	printf("Running: test_fdt_del_property\n");

	void *fdt = load_test_dtb_rw();
	const char *node_path = "/test-node";
	const char *property_name = "new-prop";

	int node_offset = fdt_path_offset(fdt, node_path);
	assert(node_offset >= 0);

	int ret = fdt_delprop(fdt, node_offset, property_name);
	assert(ret == 0);

	const char *prop = fdt_getprop(fdt, node_offset, property_name, NULL);
	assert(prop == NULL);

	printf("Deleted property %s successfully.\n", property_name);

	free(fdt);
}

// Test: Iterate through nodes
void
test_fdt_iterate_nodes()
{
	printf("Running: test_fdt_iterate_nodes\n");

	const void *fdt = load_test_dtb();
	int depth = 0;

	for (int offset = fdt_next_node(fdt, -1, &depth); offset >= 0;
	    offset = fdt_next_node(fdt, offset, &depth)) {
		const char *name = fdt_get_name(fdt, offset, NULL);
		printf("Node: %s, Depth: %d\n", name, depth);
	}

	printf("Iteration through nodes completed.\n");
}

// Main function to run all tests
int
main()
{
	printf("Starting libfdt tests...\n");

	test_fdt_open_and_check();
	test_fdt_get_property();
	test_fdt_add_property();
	test_fdt_del_property();
	test_fdt_iterate_nodes();

	printf("All tests completed successfully.\n");
	return 0;
}
