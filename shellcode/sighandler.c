#define NULL (void*)0
#define ALWAYS_INLINE inline __attribute__((always_inline))
#define	SIGQUIT 3
#define	SIGILL 4
#define	SIGTRAP 5
#define	SIGABRT 6
#define	SIGEMT 7
#define	SIGFPE 8
#define	SIGKILL 9
#define	SIGBUS 10
#define	SIGSEGV 11
#define	SIGSYS 12
#define SA_SIGINFO 0x40

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

struct mcontext {
	uint64_t mc_onstack;
	uint64_t mc_rdi;
	uint64_t mc_rsi;
	uint64_t mc_rdx;
	uint64_t mc_rcx;
	uint64_t mc_r8;
	uint64_t mc_r9;
	uint64_t mc_rax;
	uint64_t mc_rbx;
	uint64_t mc_rbp;
	uint64_t mc_r10;
	uint64_t mc_r11;
	uint64_t mc_r12;
	uint64_t mc_r13;
	uint64_t mc_r14;
	uint64_t mc_r15;
	uint32_t mc_trapno;
	uint16_t mc_fs;
	uint16_t mc_gs;
	uint64_t mc_addr;
	uint32_t mc_flags;
	uint16_t mc_es;
	uint16_t mc_ds;
	uint64_t mc_err;
	uint64_t mc_rip;
	uint64_t mc_cs;
	uint64_t mc_rflags;
	uint64_t mc_rsp;
	uint64_t mc_ss;
	uint64_t mc_len;
	uint64_t mc_fpformat;
	uint64_t mc_ownedfp;
	uint64_t mc_lbrfrom;
	uint64_t mc_lbrto;
	uint64_t mc_aux1;
	uint64_t mc_aux2;
	uint64_t mc_fpstate[104]; // NOLINT
	uint64_t mc_fsbase;
	uint64_t mc_gsbase;
	uint64_t mc_xfpustate;
	uint64_t mc_xfpustate_len;
	uint64_t mc_spare[4];
};

typedef struct sigset {
	unsigned int bits[4];
} sigset_t;

struct ucontext {
	sigset_t uc_sigmask;
	uint8_t pad[48]; // NOLINT
	struct mcontext uc_mcontext;
	// don't care
};

typedef void (*sighandler_t)(int sig);

struct sigaction {
	sighandler_t sa_handler;
	int sa_flags;
	sigset_t sa_mask;
};

typedef int (*sigaction_t)(int sig, const struct sigaction *act, struct sigaction *oact);

/*
static ALWAYS_INLINE void sigemptyset(sigset_t *restrict set) {
	set->bits[0] = 0;
    set->bits[1] = 0;
    set->bits[2] = 0;
    set->bits[3] = 0;
}
*/

extern void sighandler(int);
typedef void __attribute__((noreturn)) (*entry_t)(void *);

void __attribute__((noreturn)) sighandler_init(sigaction_t sigaction, entry_t entry, void *payload_args) {
	__asm__ volatile(
		"jmp do_init\n"
		"sighandler:\n"
		// movq $0, %r12
		".word 0xBC49\n"
		".zero 8\n"
		"call		*%r12\n"
		"movq		%rax,	%rdi\n"
		"addq		$10,	%r12\n"
		"movl		$9,		%esi\n"
		"movq		$37,	%rax\n"
		"call		*%r12\n"
		"int3\n"
		"do_init:\n"
	);
	struct sigaction action;
	__builtin_memset(&action, 0, sizeof(action));
	action.sa_handler = sighandler;
	for (int i = 2; i <= 12; i++) {
		sigaction(i, &action, NULL);
	}
	entry(payload_args);
}

//typedef int __attribute__((noreturn)) (*kill)(int pid, int sig);

typedef struct {
	void (*printBacktraceWithModuleInfo)(const char *name);
	int (*printf)(const char *fmt, ...);
	int __attribute__((noreturn)) (*kill)(int pid, int sig);
	int pid;
	const char name[16];
} handler_stuff_t;

typedef int __attribute__((noreturn)) (*kill_t)(int pid, int sig);

/*
void __attribute__((naked)) sighandler(int pid, void *v, kill_t kill) {
	__asm__ volatile(
		"movl	$9, %esi\n"
		"jmp	*%rdx\n"
	);
}
*/
