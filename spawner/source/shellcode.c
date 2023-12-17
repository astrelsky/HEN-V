#include "libs.h"
#include "memory.h"
#include "nid_resolver/resolver.h"
#include "proc.h"
#include "rtld.h"
#include "shellcode.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SHELLCODE_ADDED_INSTRUCTIONS_LENGTH 20
#define SHELLCODE_INSTRUCTIONS_LENGTH 521

#define SHELLCODE_TOTAL_LENGTH (SHELLCODE_INSTRUCTIONS_LENGTH + SHELLCODE_ADDED_INSTRUCTIONS_LENGTH)
#define SHELLCODE_INFINITE_LOOP_LENGTH 2

#define RFORK_THREAD_ADDR_OFFSET 2
#define EXTRA_STUFF_ADDR_OFFSET 12
#define INFINITE_LOOP_LENGTH 2
#define RFORK_THREAD_NID "bSDxEpGzmUE"

#define LOOKUP_SYMBOL(resolver, sym) resolver_lookup_symbol(resolver, sym, strlen(sym))

static const uint8_t BUILDER_TEMPLATE[SHELLCODE_TOTAL_LENGTH];
static const uint8_t INFINITE_LOOP[INFINITE_LOOP_LENGTH];

typedef struct {
	int sock;
	uintptr_t inf_loop; // haha open prospero go brrrrrrr
	uintptr_t func;
	uintptr_t socket;
	uintptr_t close;
	uintptr_t connect;
	uintptr_t send;
	uintptr_t kill;
	uintptr_t access;
	//uintptr_t error;
} extra_stuff_t;

static void init_extra_stuff(extra_stuff_t *restrict self, resolver_t *restrict resolver, uintptr_t loop) {
	self->sock = -1;
	self->inf_loop = loop;
	self->func = 0;
	self->socket = LOOKUP_SYMBOL(resolver, "socket");
	self->close = LOOKUP_SYMBOL(resolver, "close");
	self->connect = LOOKUP_SYMBOL(resolver, "connect");
	self->send = LOOKUP_SYMBOL(resolver, "send");
	self->kill = LOOKUP_SYMBOL(resolver, "kill");
	self->access = LOOKUP_SYMBOL(resolver, "access");
	//self->error = LOOKUP_SYMBOL(resolver, "__error");
}

int install_rfork_thread_hook(uintptr_t syscore_proc) {
	resolver_t resolver;
	process_allocator_t text_allocator;
	process_allocator_t data_allocator;

	if (get_text_allocator(&text_allocator, syscore_proc)) {
		puts("failed to get syscore .text allocator");
		return -1;
	}

	if (get_data_allocator(&data_allocator, syscore_proc)) {
		puts("failed to get syscore .data allocator");
		return -1;
	}

	uintptr_t libkernel = proc_get_lib(syscore_proc, LIBKERNEL_HANDLE);
	if (libkernel == 0) {
		puts("failed to find syscore libkernel");
		return -1;
	}

	uintptr_t imagebase = shared_lib_get_imagebase(libkernel);

	if (imagebase == 0) {
		puts("syscore libkernel has an imagebase of 0");
		return -1;
	}

	uintptr_t meta = shared_lib_get_metadata(libkernel);
	if (meta == 0) {
		puts("syscore libkernel has no metadata");
		return -1;
	}

	resolver_init(&resolver);

	if (resolver_add_library_metadata(&resolver, imagebase, meta) != 0) {
		puts("failed to add syscore libkernel metadata to the resolver");
		resolver_finalize(&resolver);
		return -1;
	}

	uintptr_t code = process_allocator_allocate(&text_allocator, SHELLCODE_TOTAL_LENGTH);
	uintptr_t loop = process_allocator_allocate(&text_allocator, INFINITE_LOOP_LENGTH);
	printf("infinite loop address 0x%08llx\n", loop);

	uintptr_t rfork_thread = LOOKUP_SYMBOL(&resolver, "rfork_thread");
	uintptr_t p_extra_stuff = process_allocator_allocate(&data_allocator, sizeof(extra_stuff_t));
	extra_stuff_t extra_stuff;
	init_extra_stuff(&extra_stuff, &resolver, loop);
	resolver_finalize(&resolver);

	const int pid = proc_get_pid(syscore_proc);
	userland_copyin(pid, &extra_stuff, p_extra_stuff, sizeof(extra_stuff));
	userland_copyin(pid, INFINITE_LOOP, loop, INFINITE_LOOP_LENGTH);

	uintptr_t eboot = proc_get_eboot(syscore_proc);
	if (eboot == 0) {
		puts("failed to get syscore eboot");
		return -1;
	}

	uintptr_t eboot_metadata = shared_lib_get_metadata(eboot);
	if (eboot_metadata == 0) {
		puts("failed to get syscore eboot metadata");
		return -1;
	}

	const size_t plt_offset = metadata_get_plt_offset(eboot_metadata, RFORK_THREAD_NID);
	if (plt_offset == 0) {
		puts("failed to get syscore's rfork_thread import");
		return -1;
	}

	const uintptr_t syscore_base = shared_lib_get_imagebase(eboot);

	printf("syscore imagebase: 0x%08llx\n", syscore_base);

	const uintptr_t imported_rfork_thread = plt_offset + syscore_base;

	uint8_t *shellcode = malloc(SHELLCODE_TOTAL_LENGTH);
	if (shellcode == 0) {
		puts("failed to allocate memory for shellcode");
		return -1;
	}

	memcpy(shellcode, BUILDER_TEMPLATE, SHELLCODE_TOTAL_LENGTH);
	*(uintptr_t*)(shellcode + RFORK_THREAD_ADDR_OFFSET) = rfork_thread;
	*(uintptr_t*)(shellcode + EXTRA_STUFF_ADDR_OFFSET) = p_extra_stuff;
	userland_copyin(pid, shellcode, code, SHELLCODE_TOTAL_LENGTH);
	free(shellcode);

	userland_copyin(pid, &code, imported_rfork_thread, sizeof(code));
	return 0;
}

static const uint8_t BUILDER_TEMPLATE[] = {
	0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV rfork_thread, R8
	0x49, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV &stuff, R9
	0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x81, 0xec, 0xa8, 0x00, 0x00,
	0x00, 0x48, 0x8b, 0x41, 0x10, 0x4c, 0x89, 0xcb, 0x49, 0x89, 0xcf, 0x49, 0x89, 0xd6, 0x48, 0x89,
	0xf5, 0x44, 0x8b, 0x60, 0x0d, 0x41, 0x81, 0xfc, 0x48, 0x45, 0x4e, 0x56, 0x75, 0x15, 0x83, 0x3b,
	0xff, 0x0f, 0x84, 0x8c, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x53, 0x08, 0x41, 0xb5, 0x01, 0xe9, 0x1f,
	0x01, 0x00, 0x00, 0x49, 0x83, 0x7f, 0x08, 0x00, 0x0f, 0x84, 0x0e, 0x01, 0x00, 0x00, 0xc5, 0xf8,
	0x10, 0x00, 0xc5, 0xf8, 0x10, 0x48, 0x0a, 0x48, 0xb8, 0x2f, 0x61, 0x70, 0x70, 0x30, 0x2f, 0x68,
	0x6f, 0x31, 0xf6, 0x49, 0x89, 0xed, 0x4c, 0x89, 0xc5, 0xc5, 0xf8, 0x11, 0x4c, 0x24, 0x2a, 0xc5,
	0xf8, 0x29, 0x44, 0x24, 0x20, 0x48, 0x89, 0x44, 0x24, 0x3a, 0x48, 0xb8, 0x6d, 0x65, 0x62, 0x72,
	0x65, 0x77, 0x2e, 0x65, 0x48, 0x89, 0x44, 0x24, 0x42, 0x48, 0xc7, 0x44, 0x24, 0x4a, 0x6c, 0x66,
	0x00, 0x00, 0x44, 0x89, 0x64, 0x24, 0x08, 0x41, 0x89, 0xfc, 0x48, 0x8d, 0x7c, 0x24, 0x20, 0xff,
	0x53, 0x40, 0x44, 0x89, 0xe7, 0x44, 0x8b, 0x64, 0x24, 0x08, 0x49, 0x89, 0xe8, 0x4c, 0x89, 0xed,
	0x45, 0x31, 0xed, 0x4c, 0x89, 0xf2, 0x85, 0xc0, 0x0f, 0x85, 0xa4, 0x00, 0x00, 0x00, 0xe9, 0x6b,
	0xff, 0xff, 0xff, 0x89, 0x7c, 0x24, 0x14, 0x49, 0xbd, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d,
	0x5f, 0x48, 0xb8, 0x74, 0x6d, 0x70, 0x2f, 0x49, 0x50, 0x43, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
	0xbe, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x4c, 0x89, 0x44, 0x24, 0x18, 0x4c, 0x89, 0x74, 0x24,
	0x08, 0x4c, 0x89, 0xac, 0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xa0, 0x00, 0x00,
	0x00, 0xff, 0x53, 0x18, 0x89, 0x03, 0x83, 0xf8, 0xff, 0x0f, 0x84, 0xdf, 0x00, 0x00, 0x00, 0x41,
	0x89, 0xc6, 0x48, 0xb8, 0x74, 0x6d, 0x70, 0x2f, 0x49, 0x50, 0x43, 0x00, 0x48, 0x8d, 0x74, 0x24,
	0x20, 0xba, 0x11, 0x00, 0x00, 0x00, 0xc6, 0x44, 0x24, 0x20, 0x00, 0xc6, 0x44, 0x24, 0x21, 0x01,
	0x4c, 0x89, 0x6c, 0x24, 0x22, 0x44, 0x89, 0xf7, 0x48, 0x89, 0x44, 0x24, 0x2a, 0xff, 0x53, 0x28,
	0x83, 0xf8, 0xff, 0x0f, 0x84, 0x99, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0x74, 0x24, 0x08, 0x4c, 0x8b,
	0x44, 0x24, 0x18, 0x8b, 0x7c, 0x24, 0x14, 0xe9, 0xdb, 0xfe, 0xff, 0xff, 0x45, 0x31, 0xed, 0x4c,
	0x89, 0xf2, 0x48, 0x89, 0xee, 0x4c, 0x89, 0xf9, 0x41, 0xff, 0xd0, 0x83, 0xf8, 0xff, 0x74, 0x7e,
	0xc7, 0x44, 0x24, 0x20, 0x01, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x24, 0x89, 0xc5, 0x31, 0xc0,
	0x45, 0x84, 0xed, 0x4c, 0x89, 0x7c, 0x24, 0x28, 0x49, 0x0f, 0x45, 0xc6, 0x44, 0x8b, 0x33, 0x48,
	0x89, 0x44, 0x24, 0x30, 0x44, 0x89, 0x64, 0x24, 0x38, 0x41, 0x83, 0xfe, 0xff, 0x74, 0x1b, 0x48,
	0x8d, 0x74, 0x24, 0x20, 0x44, 0x89, 0xf7, 0xba, 0x20, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x02,
	0x00, 0xff, 0x53, 0x30, 0x48, 0x83, 0xf8, 0xff, 0x74, 0x05, 0x41, 0x89, 0xee, 0xeb, 0x35, 0x44,
	0x89, 0xf7, 0xff, 0x53, 0x20, 0x41, 0xbe, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x03, 0xff, 0xff, 0xff,
	0xff, 0x45, 0x84, 0xed, 0x74, 0x1e, 0x89, 0xef, 0xbe, 0x09, 0x00, 0x00, 0x00, 0xff, 0x53, 0x38,
	0xeb, 0x12, 0x44, 0x89, 0xf7, 0xff, 0x53, 0x20, 0xc7, 0x03, 0xff, 0xff, 0xff, 0xff, 0x41, 0xbe,
	0xff, 0xff, 0xff, 0xff, 0x44, 0x89, 0xf0, 0x48, 0x81, 0xc4, 0xa8, 0x00, 0x00, 0x00, 0x5b, 0x41,
	0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3
};

static const uint8_t INFINITE_LOOP[] = {0xeb, 0xfe};
