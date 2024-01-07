// Required header

#ifndef _MMAP_DECLARED
#define _MMAP_DECLARED
#endif

#include <ps5/payload_main.h>
#include <ps5/kernel.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// NOLINTBEGIN(*)

#define libkernel 0x2001
#define nullptr 0

extern uintptr_t kernel_base;
void *f_get_authinfo = nullptr;
uintptr_t __attribute__((used)) syscall_addr = 0;

extern int main(int argc, const char **argv);

static __attribute__ ((used)) void *f_sceKernelDlsym = nullptr;
int __attribute__ ((naked)) sceKernelDlsym(int lib, const char *name, void **fun) {
	__asm__ volatile("jmp *f_sceKernelDlsym(%rip)");
}

static __attribute__ ((used)) void *f_sceKernelLoadStartModule = nullptr;
int __attribute__ ((naked)) sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, uint32_t flags, void *unknown, int *result) {
	__asm__ volatile("jmp *f_sceKernelLoadStartModule(%rip)");
}

#define STUB(fname) \
static __attribute__ ((used)) void *f_##fname = nullptr;\
int __attribute__ ((naked)) fname(void) {\
	__asm__ volatile("jmp *f_"#fname"(%rip)");\
}

// int sceKernelLoadStartModule(char *name, size_t argc, void *argv, uint32_t flags, void *unknown, int *result)

static __attribute__ ((used)) void *f_usleep = nullptr;
int __attribute__ ((naked)) usleep(unsigned int useconds) {
	__asm__ volatile("jmp *f_usleep(%rip)");
}

static __attribute__ ((used)) void *f_close = nullptr;
int __attribute__ ((naked)) close(int fd) {
	__asm__ volatile("jmp *f_close(%rip)");
}

static __attribute__ ((used)) void *f_puts = nullptr;
int __attribute__ ((naked)) puts(const char *msg) {
	__asm__ volatile("jmp *f_puts(%rip)");
}

static __attribute__ ((used)) void *f_free = nullptr;
void __attribute__ ((naked)) free(void *ptr) {
	__asm__ volatile("jmp *f_free(%rip)");
}

static __attribute__ ((used)) void *f_malloc = nullptr;
void *__attribute__ ((naked)) malloc(size_t size) {
	__asm__ volatile("jmp *f_malloc(%rip)");
}

static __attribute__ ((used)) void *f_dup = nullptr;
int __attribute__ ((naked)) dup(int oldd) {
	__asm__ volatile("jmp *f_dup(%rip)");
}

static __attribute__ ((used)) void *f_dup2 = nullptr;
int __attribute__ ((naked)) dup2(int oldd, int newd) {
	__asm__ volatile("jmp *f_dup2(%rip)");
}

static __attribute__ ((used)) void *f_kill = nullptr;
int __attribute__ ((naked))	kill(__pid_t pid, int n) {
	__asm__ volatile("jmp *f_kill(%rip)");
}

int __attribute__ ((naked, noinline)) mdbg_call(void) {
	__asm__ volatile(
		"mov $573, %rax\n"
		"jmp *syscall_addr(%rip)\n"
	);
}

int __attribute__ ((naked, noinline)) ptrace(void) {
	__asm__ volatile(
		"mov $26, %rax\n"
		"jmp *syscall_addr(%rip)\n"
	);
}

int __attribute__ ((naked, noinline)) nmount(void) {
	__asm__ volatile(
		"mov $378, %rax\n"
		"jmp *syscall_addr(%rip)\n"
	);
}

static __attribute__ ((used)) void *f_unlink = nullptr;
int __attribute__ ((naked))	unlink(const char *path) {
	__asm__ volatile("jmp *f_unlink(%rip)");
}

static __attribute__ ((used)) void *f_realloc = nullptr;
void *__attribute__ ((naked)) realloc(void *ptr, size_t length) {
	__asm__ volatile("jmp *f_realloc(%rip)");
}

static __attribute__ ((used)) void *f_perror = nullptr;
void __attribute__ ((naked))	perror(const char *msg) {
	__asm__ volatile("jmp *f_perror(%rip)");
}

static __attribute__ ((used)) void *f_signal = nullptr;
__sighandler_t *__attribute__ ((naked)) signal(int a, __sighandler_t *b) {
	__asm__ volatile("jmp *f_signal(%rip)");
}

static __attribute__ ((used)) void *f_setjmp = nullptr;
int __attribute__ ((naked)) setjmp(jmp_buf env) {
	__asm__ volatile("jmp *f_setjmp(%rip)");
}

static __attribute__ ((used)) void *f_longjmp = nullptr;
void __attribute__ ((naked)) longjmp(jmp_buf env, int val) {
	__asm__ volatile("jmp *f_longjmp(%rip)");
}

STUB(sceUserServiceGetForegroundUser)
STUB(getpid)
STUB(getppid)
STUB(memset)
STUB(putchar)
STUB(memcpy)
STUB(memcmp)
STUB(strcmp)
STUB(socket)
STUB(bind)
STUB(listen)
STUB(accept)
STUB(setsockopt)
STUB(_write)
STUB(_read)
STUB(open)
STUB(mkdir)
STUB(stat)
STUB(printf)
STUB(snprintf)
STUB(strstr)
STUB(strlen)
STUB(strnlen)
STUB(sysctlbyname)
STUB(strncpy)
STUB(strncmp)
STUB(__error)
STUB(strerror)
STUB(sceKernelPrintBacktraceWithModuleInfo)
STUB(waitpid)
STUB(sysctl)
STUB(pthread_create)
STUB(pthread_join)

STUB(sceSysmoduleLoadModuleInternal)

STUB(fopen)
STUB(fwrite)
STUB(fclose)
STUB(fread)

// these are unused
STUB(sceSysmoduleLoadModuleByNameInternal)
STUB(mmap)
STUB(munmap)
STUB(sceKernelJitCreateSharedMemory)

STUB(strrchr)

STUB(connect)
STUB(inet_addr)

#define LINK(lib, fname) sceKernelDlsym(lib, #fname, &f_##fname)
#define LIBKERNEL_LINK(fname) LINK(libkernel, fname)
#define LIBC_LINK(fname) LINK(libc, fname)

#define STDOUT 1
#define STDERR 2
#define SYSCALL_OFFSET 7

jmp_buf g_catch_buf;

void _start(struct payload_args *args) {

	f_sceKernelDlsym = (void*)args->dlsym;
	LIBKERNEL_LINK(sceKernelLoadStartModule);
	int libc = sceKernelLoadStartModule("libSceLibcInternal.sprx", 0, 0, 0, 0, 0);
	LIBC_LINK(puts);
	puts("_start entered");
	LIBKERNEL_LINK(dup);
	LIBKERNEL_LINK(dup2);
	LIBKERNEL_LINK(socket);
	LIBKERNEL_LINK(setsockopt);
	LIBKERNEL_LINK(bind);
	LIBKERNEL_LINK(listen);
	LIBKERNEL_LINK(accept);
	LIBKERNEL_LINK(usleep);
	LIBKERNEL_LINK(getpid);
	LIBKERNEL_LINK(getppid);
	LIBKERNEL_LINK(get_authinfo);
	syscall_addr = (uintptr_t)f_get_authinfo + SYSCALL_OFFSET;

	LIBKERNEL_LINK(_write);
	LIBKERNEL_LINK(_read);
	LIBKERNEL_LINK(open);
	LIBKERNEL_LINK(close);
	LIBKERNEL_LINK(mkdir);
	LIBKERNEL_LINK(stat);
	LIBKERNEL_LINK(unlink);
	LIBKERNEL_LINK(sysctlbyname);
	LIBKERNEL_LINK(__error);
	LIBKERNEL_LINK(sceKernelPrintBacktraceWithModuleInfo);
	LIBKERNEL_LINK(waitpid);
	LIBKERNEL_LINK(pthread_create);
	LIBKERNEL_LINK(pthread_join);
	LIBKERNEL_LINK(kill);
	LIBKERNEL_LINK(sysctl);
	LIBKERNEL_LINK(signal);
	LIBC_LINK(setjmp);
	LIBC_LINK(longjmp);
	LIBC_LINK(inet_addr);
	LIBKERNEL_LINK(connect);

	if (f_setjmp == NULL) {
		puts("failed to resolve setjmp");
		return;
	}

	if (f_longjmp == NULL) {
		puts("failed to resolve longjmp");
		return;
	}

	LIBC_LINK(memset);
	LIBC_LINK(putchar);
	LIBC_LINK(malloc);
	LIBC_LINK(free);
	LIBC_LINK(memcpy);
	LIBC_LINK(memcmp);
	LIBC_LINK(strcmp);
	LIBC_LINK(printf);
	LIBC_LINK(snprintf);
	LIBC_LINK(perror);
	LIBC_LINK(realloc);
	LIBC_LINK(strrchr);

	LIBC_LINK(strstr);
	LIBC_LINK(strlen);
	LIBC_LINK(strnlen);
	LIBC_LINK(strncpy);
	LIBC_LINK(strncmp);
	LIBC_LINK(strerror);

	LIBC_LINK(fopen);
	LIBC_LINK(fwrite);
	LIBC_LINK(fclose);
	LIBC_LINK(fread);

	int libSceSysmodule = sceKernelLoadStartModule("libSceSysmodule.sprx", 0, 0, 0, 0, 0);

	LINK(libSceSysmodule, sceSysmoduleLoadModuleInternal);
	LINK(libSceSysmodule, sceSysmoduleLoadModuleByNameInternal);

	kernel_base = args->kdata_base_addr;
	kernel_init_rw(args->rwpair[0], args->rwpair[1], args->rwpipe, args->kpipe_addr);

	//int origStdout = dup(STDOUT);
	//int origStderr = dup(STDERR);

	// stdout/stderr is set in main
	puts("setjmp");
	if (setjmp(g_catch_buf) == 0) {
		puts("calling main");
		*args->payloadout = main(0, NULL);
	} else {
		puts("fatal error caught successfully");
	}
	//dup2(origStdout, STDOUT);
	//dup2(origStderr, STDERR);
}

// NOLINTEND(*)
