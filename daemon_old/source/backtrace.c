#include <stdint.h>
#include <stdio.h>

typedef struct frame frame_t;

typedef struct frame {
	frame_t *next;
	uintptr_t addr;
} frame_t;

const frame_t *__attribute__((naked)) get_frame_pointer(void) {
	__asm__ volatile(
		"push %rbp\n"
		"pop %rax\n"
		"ret\n"
	);
}

static uintptr_t __attribute__((naked, noinline)) get_text_start(void) {
	__asm__ volatile(
		"lea __text_start(%rip), %rax\n"
		"ret\n"
	);
}

static uintptr_t __attribute__((naked, noinline)) get_text_end(void) {
	__asm__ volatile(
		"lea __text_stop(%rip), %rax\n"
		"ret\n"
	);
}

void print_backtrace(void) {
	const uintptr_t start = get_text_start();
	const uintptr_t stop = get_text_end();
	__builtin_printf(".text: 0x%08llx\n", (unsigned long long)start);
	puts("---backtrace start---");
	for (const frame_t *__restrict frame = get_frame_pointer(); frame != NULL; frame = frame->next) {
		if (frame->addr != 0) {
			if (frame->addr >= start && frame->addr <= stop) {
				__builtin_printf("0x%llx ", (unsigned long long)frame->addr - start);
			}
		}
	}
	puts("\n---backtrace end---");
}
