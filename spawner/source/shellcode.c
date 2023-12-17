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
#define SHELLCODE_INSTRUCTIONS_LENGTH 878

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
	uintptr_t recv;
	uintptr_t access;
} extra_stuff_t;

static void init_extra_stuff(extra_stuff_t *restrict self, resolver_t *restrict resolver, uintptr_t loop) {
	self->sock = -1;
	self->inf_loop = loop;
	self->func = 0;
	self->socket = LOOKUP_SYMBOL(resolver, "socket");
	self->close = LOOKUP_SYMBOL(resolver, "close");
	self->connect = LOOKUP_SYMBOL(resolver, "connect");
	self->send = LOOKUP_SYMBOL(resolver, "send");
	self->recv = LOOKUP_SYMBOL(resolver, "recv");
	self->access = LOOKUP_SYMBOL(resolver, "access");
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

	const uintptr_t imported_rfork_thread = plt_offset + shared_lib_get_imagebase(eboot);

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
	0x00, 0x4d, 0x89, 0xce, 0x48, 0x89, 0xcb, 0x49, 0x89, 0xd4, 0x49, 0x89, 0xf5, 0x89, 0xfd, 0x48,
	0x85, 0xc9, 0x0f, 0x84, 0xca, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x4b, 0x08, 0x48, 0x85, 0xc9, 0x0f,
	0x84, 0xbd, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x43, 0x10, 0x48, 0x85, 0xc0, 0x0f, 0x84, 0xb0, 0x00,
	0x00, 0x00, 0x48, 0xbe, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x48, 0xba, 0x65, 0x78,
	0x2f, 0x61, 0x70, 0x70, 0x2f, 0x48, 0x48, 0xbf, 0x45, 0x4e, 0x56, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x48, 0x89, 0x74, 0x24, 0x20, 0x48, 0x89, 0x54, 0x24, 0x28, 0x48, 0x89, 0x7c, 0x24, 0x30, 0xc5,
	0xf9, 0x6f, 0x44, 0x24, 0x20, 0xc5, 0xfa, 0x7e, 0x4c, 0x24, 0x30, 0xc5, 0xfa, 0x7e, 0x51, 0x10,
	0xc5, 0xf9, 0xef, 0x01, 0xc5, 0xf1, 0xef, 0xca, 0xc5, 0xf1, 0xeb, 0xc0, 0xc4, 0xe2, 0x79, 0x17,
	0xc0, 0x0f, 0x84, 0xca, 0x00, 0x00, 0x00, 0xc5, 0xfa, 0x6f, 0x00, 0xc5, 0xfa, 0x6f, 0x48, 0x0a,
	0x48, 0xb8, 0x2f, 0x61, 0x70, 0x70, 0x30, 0x2f, 0x68, 0x6f, 0x48, 0x8d, 0x7c, 0x24, 0x20, 0x31,
	0xf6, 0x4d, 0x89, 0xc7, 0xc5, 0xfa, 0x7f, 0x4c, 0x24, 0x2a, 0xc5, 0xf9, 0x7f, 0x44, 0x24, 0x20,
	0x48, 0x89, 0x44, 0x24, 0x3a, 0x48, 0xb8, 0x6d, 0x65, 0x62, 0x72, 0x65, 0x77, 0x2e, 0x65, 0x48,
	0x89, 0x44, 0x24, 0x42, 0x48, 0xc7, 0x44, 0x24, 0x4a, 0x6c, 0x66, 0x00, 0x00, 0x41, 0xff, 0x56,
	0x40, 0x48, 0xbe, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x4d, 0x89, 0xf8, 0x85, 0xc0,
	0x74, 0x6f, 0x89, 0xef, 0x4c, 0x89, 0xee, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xd9, 0x41, 0xff, 0xd0,
	0x41, 0x8b, 0x2e, 0x41, 0x89, 0xc7, 0x83, 0xfd, 0xff, 0x0f, 0x84, 0x22, 0x02, 0x00, 0x00, 0x48,
	0x8b, 0x43, 0x10, 0xc7, 0x44, 0x24, 0x20, 0x01, 0x00, 0x00, 0x00, 0x44, 0x89, 0x7c, 0x24, 0x24,
	0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x74, 0x24, 0x20, 0x89, 0xef,
	0xba, 0x18, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x02, 0x00, 0x8b, 0x40, 0x0d, 0x89, 0x44, 0x24,
	0x30, 0x41, 0xff, 0x56, 0x30, 0x48, 0x83, 0xf8, 0xff, 0x0f, 0x85, 0xe2, 0x01, 0x00, 0x00, 0x89,
	0xef, 0x41, 0xff, 0x56, 0x20, 0x41, 0xc7, 0x06, 0xff, 0xff, 0xff, 0xff, 0xe9, 0xd0, 0x01, 0x00,
	0x00, 0x48, 0xb8, 0x74, 0x6d, 0x70, 0x2f, 0x49, 0x50, 0x43, 0x00, 0x4c, 0x89, 0x04, 0x24, 0x48,
	0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x44, 0x24, 0x18, 0x45, 0x8b, 0x3e, 0x41, 0x83, 0xff, 0xff,
	0x74, 0x76, 0x48, 0x8d, 0xb4, 0x24, 0x90, 0x00, 0x00, 0x00, 0x44, 0x89, 0xff, 0xba, 0x18, 0x00,
	0x00, 0x00, 0xb9, 0x00, 0x00, 0x02, 0x00, 0xc7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x48, 0xc7, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x84,
	0x24, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xff, 0x56, 0x30, 0x48, 0x83, 0xf8,
	0xff, 0x0f, 0x84, 0x8c, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x74, 0x24, 0x20, 0x44, 0x89, 0xff, 0xba,
	0x04, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x02, 0x00, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00,
	0x00, 0x41, 0xff, 0x56, 0x38, 0x48, 0x83, 0xf8, 0xff, 0x74, 0x60, 0x83, 0x7c, 0x24, 0x20, 0x01,
	0x0f, 0x84, 0xc2, 0x00, 0x00, 0x00, 0xeb, 0x53, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe, 0x01, 0x00,
	0x00, 0x00, 0x31, 0xd2, 0x41, 0xff, 0x56, 0x18, 0x41, 0x89, 0x06, 0x83, 0xf8, 0xff, 0x0f, 0x84,
	0x0c, 0x01, 0x00, 0x00, 0xc6, 0x44, 0x24, 0x20, 0x00, 0xc6, 0x44, 0x24, 0x21, 0x01, 0x41, 0x89,
	0xc7, 0x48, 0x8d, 0x74, 0x24, 0x20, 0xba, 0x11, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x10,
	0x44, 0x89, 0xff, 0x48, 0x89, 0x44, 0x24, 0x22, 0x48, 0x8b, 0x44, 0x24, 0x18, 0x48, 0x89, 0x44,
	0x24, 0x2a, 0x41, 0xff, 0x56, 0x28, 0x83, 0xf8, 0xff, 0x75, 0x6d, 0x44, 0x89, 0xff, 0xe9, 0xc2,
	0x00, 0x00, 0x00, 0x49, 0x8b, 0x46, 0x20, 0x44, 0x89, 0xff, 0x48, 0x89, 0x44, 0x24, 0x08, 0xff,
	0xd0, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xbe, 0x01, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x41, 0xff, 0x56,
	0x18, 0x41, 0x89, 0x06, 0x83, 0xf8, 0xff, 0x0f, 0x84, 0x9c, 0x00, 0x00, 0x00, 0xc6, 0x44, 0x24,
	0x20, 0x00, 0xc6, 0x44, 0x24, 0x21, 0x01, 0x41, 0x89, 0xc7, 0x48, 0x8d, 0x74, 0x24, 0x20, 0xba,
	0x11, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x10, 0x44, 0x89, 0xff, 0x48, 0x89, 0x44, 0x24,
	0x22, 0x48, 0x8b, 0x44, 0x24, 0x18, 0x48, 0x89, 0x44, 0x24, 0x2a, 0x41, 0xff, 0x56, 0x28, 0x83,
	0xf8, 0xff, 0x0f, 0x84, 0xad, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x04, 0x24, 0x49, 0x8b, 0x56, 0x08,
	0x89, 0xef, 0x4c, 0x89, 0xee, 0x48, 0x89, 0xd9, 0x44, 0x89, 0x7c, 0x24, 0x08, 0xff, 0xd0, 0xc7,
	0x44, 0x24, 0x20, 0x01, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x24, 0x41, 0x89, 0xc7, 0x48, 0x8b,
	0x43, 0x10, 0x4c, 0x89, 0x64, 0x24, 0x28, 0x8b, 0x7c, 0x24, 0x08, 0x48, 0x8d, 0x74, 0x24, 0x20,
	0xba, 0x18, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x02, 0x00, 0x8b, 0x40, 0x0d, 0x89, 0x44, 0x24,
	0x30, 0x41, 0xff, 0x56, 0x30, 0x48, 0x83, 0xf8, 0xff, 0x74, 0x3b, 0x41, 0x83, 0xff, 0xff, 0x75,
	0x20, 0x8b, 0x7c, 0x24, 0x08, 0x41, 0xff, 0x56, 0x20, 0x41, 0xc7, 0x06, 0xff, 0xff, 0xff, 0xff,
	0x89, 0xef, 0x4c, 0x89, 0xee, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xd9, 0xff, 0x14, 0x24, 0x41, 0x89,
	0xc7, 0x44, 0x89, 0xf8, 0x48, 0x81, 0xc4, 0xa8, 0x00, 0x00, 0x00, 0x5b, 0x41, 0x5c, 0x41, 0x5d,
	0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3, 0x8b, 0x7c, 0x24, 0x08, 0x41, 0xff, 0x56, 0x20, 0x89, 0xef,
	0x4c, 0x89, 0xee, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xd9, 0x41, 0xc7, 0x06, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x14, 0x24, 0xeb, 0xcc, 0x44, 0x89, 0xff, 0xff, 0x54, 0x24, 0x08, 0xeb, 0xab
};

static const uint8_t INFINITE_LOOP[] = {0xeb, 0xfe};
