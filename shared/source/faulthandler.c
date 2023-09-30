#include "faulthandler.h"

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct frame frame_t;

typedef struct frame {
	frame_t *next;
	uintptr_t addr;
} frame_t;

static void (*g_cleanup_handler)(void) = NULL;

static frame_t *__attribute__((naked)) get_frame_pointer_head(void) {
	__asm__ volatile(
		"push %rbp\n"
		"pop %rax\n"
		"ret\n"
	);
}

static inline frame_t *get_frame_pointer(void) {
	// skip whatever function is getting the frame pointer
	frame_t *head = get_frame_pointer_head();
	return head != NULL ? head->next : NULL;
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

// NOLINTBEGIN(bugprone-signal-handler)

//
static void print_backtrace(void) {
	const uintptr_t start = get_text_start();
	const uintptr_t stop = get_text_end();
	printf(".text: 0x%08llx\n", (unsigned long long)start);
	puts("---backtrace start---");
	for (const frame_t *__restrict frame = get_frame_pointer(); frame != NULL; frame = frame->next) {
		if (frame->addr != 0) {
			if (frame->addr >= start && frame->addr <= stop) {
				printf("0x%llx ", (unsigned long long)frame->addr - start);
			} else {
				printf("0x%llx ", frame->addr);
			}
		}
	}
	puts("\n---backtrace end---");
}

extern void shutdown_ipc(void);
extern void kill_loading_app(void);

static void __attribute__((used)) cleanup_and_throw(void) {
	puts("Fatal error occured. Cleaning up and punting...");
	if (g_cleanup_handler != NULL) {
		g_cleanup_handler();
		g_cleanup_handler = NULL;
	}
	longjmp(g_catch_buf, 1);
	// TODO longjump here
}

static uintptr_t __attribute__((naked, noinline)) get_cleanup_function(void) {
	__asm__ volatile(
		"lea cleanup_and_throw(%rip), %rax\n"
		"ret\n"
	);
}

static void fault_handler(int sig) {
	printf("signal %d received\n", sig);
	if (sig == SIGSEGV || sig == SIGILL) {
		print_backtrace();
		frame_t *frame = get_frame_pointer();
		frame->addr = get_cleanup_function();
	}
}

// NOLINTEND(bugprone-signal-handler)

void fault_handler_init(void (*cleanup_handler)(void)) {
	g_cleanup_handler = cleanup_handler;
	signal(SIGSEGV, fault_handler);
	signal(SIGILL, fault_handler);
}
