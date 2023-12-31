#pragma once

#include <stdint.h>
#include <stddef.h> // IWYU pragma: keep
#include <unistd.h>

#define PROC_UCRED_OFFSET 0x40

extern const uintptr_t kernel_base; // NOLINT

void kernel_copyin(const void *src, uint64_t kdest, size_t length);
void kernel_copyout(uint64_t ksrc, void *dest, size_t length);

static inline uintptr_t proc_get_ucred(uintptr_t proc) {
	uintptr_t ucred = 0;
	kernel_copyout(proc + PROC_UCRED_OFFSET, &ucred, sizeof(ucred));
	return ucred;
}

void userland_copyin(int pid, const void *src, uintptr_t dst, size_t length);

void userland_copyout(int pid, uintptr_t src, void *dst, size_t length);
