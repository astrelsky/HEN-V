#define TITLEID_LENGTH 10
#define HENV 0x564E4548
#define F_OK 0
#define NULL 0

// AF_UNIX address family
#define AF_UNIX 1

// Maximum length of the sun_path field
#define UNIX_PATH_MAX 104

#define SIN_ZERO_SIZE 8

#define PROCESS_LAUNCHED 1
#define MSG_NOSIGNAL    0x20000
#define	SIGKILL 9
#define TITLEID_OFFSET 0xd

// NOLINTBEGIN(*)

typedef struct {
	const char *arg0; // /app0/eboot.bin
	const char *path; // /system_ex/app/BREW00000/eboot.bin
	const char *sandboxPath; // /mnt/sandbox/BREW00000_000
	// remaining unknown
} procSpawnArgs;

typedef int (*func_t)(void*);
typedef int (*rfork_thread_t)(int flags, void *stack, func_t func, void *arg);

struct sockaddr_un {
	unsigned char sun_len;
    unsigned char sun_family;    // AF_UNIX
    char sun_path[104];        // Path name
};

typedef struct {
	int sock;
	int daemonPid;
	const func_t inf_loop; // haha open prospero go brrrrrrr
	func_t func;
	int (*socket)(int domain, int type, int protocol);
	int (*close)(int fd);
    int (*connect)(int s, void *name, unsigned int namelen);
	long (*send)(int sockfd, const void *buf, int len, int flags);
	int (*kill)(int pid, int sig);
	int (*access)(const char *path, int flags);
	//int *(*__error)(void);
} ExtraStuff;

struct result {
	int cmd;
	int pid;
	void *args;
	func_t func;
	unsigned int prefix;
};

// INFINITE_LOOP: 0xeb 0xfe

// insert a "MOV rfork_thread, R8" at the beginning of the hook shellcode
// insert a "MOV &stuff, R9" at the beginning of the hook shellcode
/*
49 b8 xx xx xx xx xx xx xx xx
49 b9 xx xx xx xx xx xx xx xx
*/

#define SOCK_STREAM 1
#define SERVER_SIZE 15 + 2
#define IPC_PATH_LENGTH 16


static inline int __attribute__((always_inline)) reconnect(ExtraStuff *restrict stuff) {
	volatile unsigned long ipc[2];
	ipc[0] = 0x5f6d65747379732f;
	ipc[1] = 0x004350492f706d74;
    volatile struct sockaddr_un server;
	if (stuff->sock != -1) {
		stuff->close(stuff->sock);
	}
    stuff->sock = stuff->socket(AF_UNIX, SOCK_STREAM, 0);
	if (stuff->sock == -1) {
		return -1;
	}

	server.sun_len = 0;
    server.sun_family = AF_UNIX;
	__builtin_memcpy((char*)server.sun_path, (void*)ipc, IPC_PATH_LENGTH);

    if (stuff->connect(stuff->sock, (void*)&server, SERVER_SIZE) == -1){
		stuff->close(stuff->sock);
		stuff->sock = -1;
		return -1;
	}
    return 0;
}

typedef union {
	const char *str;
	volatile unsigned char *u8;
	volatile unsigned short *u16;
	volatile unsigned int *u32;
	volatile unsigned long *u64;
} string_pointer_t;

#define HOMEBREW_DAEMON_PREFIX_LENGTH 24

// /mnt/sandbox/xxxxyyyyy_000/app0/homebrew.elf
#define SANDBOX_PATH_LENGTH 26
#define HOMEBREW_PATH_LENGTH 48

static inline char *__attribute__((always_inline)) copySandboxPath(char *restrict dst, const char *restrict src) {
	return (char *)__builtin_memcpy(dst, src, SANDBOX_PATH_LENGTH) + SANDBOX_PATH_LENGTH;
}

static inline int __attribute__((always_inline)) isHomebrew(ExtraStuff *restrict stuff, procSpawnArgs *restrict arg) {
	if (arg == NULL || arg->path == NULL || arg->sandboxPath == NULL) {
		// some safety checks
		return 0;
	}

	char path[HOMEBREW_PATH_LENGTH];
	volatile unsigned long *dst = (unsigned long *)copySandboxPath(path, arg->sandboxPath);
	dst[0] = 0x6F682F307070612F;
	dst[1] = 0x652E77657262656D;
	dst[2] = 0x666C;
	return stuff->access(path, F_OK) == 0;
}

static inline unsigned int __attribute__((always_inline)) getTitleIdPrefix(procSpawnArgs *restrict arg) {
	return *(unsigned int *)(arg->sandboxPath + TITLEID_OFFSET);
}

static int __attribute__((used)) rfork_thread_hook(int flags, void *stack, func_t func, procSpawnArgs *restrict arg, rfork_thread_t orig, ExtraStuff *restrict stuff) {
	const unsigned int prefix = getTitleIdPrefix(arg);
	const int homebrew = prefix == HENV || isHomebrew(stuff, arg);
	if (homebrew && stuff->sock == -1) {
		// if this is homebrew and we're not connected, attempt to connect first
		if (reconnect(stuff) == -1) {
			//return orig(flags, stack, func, arg);
			// critical failure
			return -1;
		}
	}

	const int pid = orig(flags, stack, homebrew ? stuff->inf_loop : func, arg);

	if (pid == -1) {
		return pid;
	}

	struct result res = {
		.cmd = PROCESS_LAUNCHED,
		.pid = pid,
		.func = homebrew ? func : 0,
		.args = arg,
		.prefix = prefix,
	};

	if (stuff->sock == -1) {
		// shame
		return pid;
	}

	if (stuff->send(stuff->sock, (void *)&res, sizeof(res),  MSG_NOSIGNAL) == -1) {
		stuff->close(stuff->sock);
		stuff->sock = -1;
		if (homebrew) {
			// if we failed here and it is homebrew we need to kill the pid
			// if we don't then it'll be stuck in an infinite loop
			stuff->kill(pid, SIGKILL);
		}
		return -1;
	}

	return pid;
}

// NOLINTEND(*)
