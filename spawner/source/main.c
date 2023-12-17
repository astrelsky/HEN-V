#include "app.h"
#include "elfldr.h"
#include "faulthandler.h"
#include "jailbreak.h"
#include "libs.h"
#include "nid_resolver/resolver.h"
#include "module.h"
#include "offsets.h"
#include "rtld.h"
#include "proc.h"
#include "shellcode.h"
#include "tracer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define QAFLAGS_SIZE 16
#define USER_SERVICE_ID 0x80000011
#define SYSTEM_SERVICE_ID 0x80000010
#define LNC_UTIL_ERROR_ALREADY_RUNNING 0x8094000c
#define LNC_ERROR_APP_NOT_FOUND 0x80940031
#define ENTRYPOINT_OFFSET 0x70

#define PROCESS_LAUNCHED 1

#define LOOB_BUILDER_SIZE 21
#define LOOP_BUILDER_TARGET_OFFSET 3

#define USLEEP_NID "QcteRwbsnV0"


extern const unsigned int daemon_size;
extern uint8_t daemon_start[];

extern int _write(int fd, const void *, size_t); // NOLINT
extern ssize_t _read(int, void *, size_t); // NOLINT

#define LOOKUP_SYMBOL(resolver, sym) resolver_lookup_symbol(resolver, sym, strlen(sym))
#define SET_FUNCTION_ADDRESS(resolver, function) *(void **)&(function) = (void *)LOOKUP_SYMBOL(resolver, #function) /* NOLINT */

static uint32_t gAppId = 0;

/*
static bool runElf(Hijacker *hijacker) {

	Elf elf{hijacker, daemon_start};

	if (!elf) {
		return false;
	}

	if (elf.launch()) {
		puts("launch succeeded");
		return true;
	}
	puts("launch failed");
	return false;
}
*/

static bool load(uintptr_t proc) {
	puts("setting process name");
	proc_set_name(proc, "HEN-V");

	const int pid = proc_get_pid(proc);
	char name[PROC_SELFINFO_NAME_SIZE];
	proc_get_name(proc, name);
	__builtin_printf("new process %s pid %d\n", name, pid);
	puts("jailbreaking new process");
	jailbreak_process(proc, true);

	if (run_elf(daemon_start, pid)) {
		__builtin_printf("process name %s pid %d\n", name, pid);
		return true;
	}
	return false;
}

// NOLINTBEGIN(bugprone-reserved-identifier)

const uint8_t __text_start __attribute__((weak));
const Elf64_Rela __rela_start[1] __attribute__((weak));
const Elf64_Rela __rela_stop[1] __attribute__((weak));

// NOLINTEND(bugprone-reserved-identifier)

static bool has_unprocessed_relocations(void) {
	if (&__rela_start[0] != &__rela_stop[0]) {
		const Elf64_Rela *restrict it = __rela_start;
		return *(const char *)(&__text_start + it->r_offset) == 0;
	}
	return false;
}

static bool process_relocations(void) {
	const uintptr_t imagebase = (uintptr_t)(&__text_start);
	for (const Elf64_Rela *restrict it = __rela_start; it != __rela_stop; it++) {
		if (ELF64_R_TYPE(it->r_info) != R_X86_64_RELATIVE) {
			printf("unexpected relocation type %d\n", ELF64_R_TYPE(it->r_info));
			return false;
		}
		*(uint8_t**)(imagebase + it->r_offset) = (uint8_t*)(imagebase + it->r_addend); // NOLINT(*)
	}
	return true;
}

static void patch_syscore(void) {
	puts("patching syscore execve");
	uintptr_t syscore = get_parent_proc();
	if (syscore == 0) {
		puts("failed to find syscore proc");
		return;
	}

	if (install_rfork_thread_hook(syscore)) {
		puts("install_rfork_thread_hook failed");
	}
}


struct LncAppParam {
	uint32_t sz;
	uint32_t user_id;
	uint32_t app_opt;
	uint64_t crash_report;
	uint64_t check_flag;
};

extern int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, uint32_t flags, void *unknown, int *result);
extern int sceKernelDlsym(uint32_t lib, const char *name, void **fun);
extern int sceSysmoduleLoadModuleInternal(uint32_t);
extern int sceSysmoduleLoadModuleByNameInternal(const char *fname, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

#define GET_LIB(lib) get_lib_by_name(lib, strlen(lib))

static uintptr_t get_lib_by_name(const char *name, size_t length) {
	int64_t handle = get_module_handle(getpid(), name, length);
	if (handle == -1) {
		printf("failed to get %s\n", name);
		return 0;
	}

	uintptr_t proc = get_current_proc();
	if (proc == 0) {
		puts("failed to get current proc");
		return 0;
	}

	uintptr_t lib = proc_get_lib(proc, (int)handle);
	if (lib == 0) {
		printf("failed to get handle for %s in the current proccess\n", name);
	}
	return lib;
}

static uintptr_t get_libSceUserService(void) { // NOLINT(readability-identifier-naming)
	if (sceSysmoduleLoadModuleInternal(USER_SERVICE_ID)) {
		return 0;
	}

	return GET_LIB("libSceUserService.sprx");
}

static uintptr_t get_libSceSystemService(void) { // NOLINT(readability-identifier-naming)
	if (sceSysmoduleLoadModuleInternal(SYSTEM_SERVICE_ID)) {
		return 0;
	}

	return GET_LIB("libSceSystemService.sprx");
}

struct LaunchArgs {
	const char *titleId;
	uint32_t id;
	int *appId;
};

static uintptr_t __attribute__((used)) f_sceUserServiceInitialize = 0;
static uint32_t __attribute__ ((naked, noinline)) sceUserServiceInitialize(int *a) {
	__asm__ volatile("jmp *f_sceUserServiceInitialize(%rip)");
}

static uintptr_t __attribute__((used)) f_sceUserServiceGetForegroundUser = 0;
static uint32_t __attribute__ ((naked, noinline)) sceUserServiceGetForegroundUser(uint32_t *id) {
	__asm__ volatile("jmp *f_sceUserServiceGetForegroundUser(%rip)");
}

static uintptr_t __attribute__((used)) f_sceLncUtilLaunchApp = 0;
static int __attribute__ ((naked, noinline)) sceLncUtilLaunchApp(const char* tid, const char* argv[], struct LncAppParam* param) {
	__asm__ volatile("jmp *f_sceLncUtilLaunchApp(%rip)");
}

static uintptr_t __attribute__((used)) f_sceLncUtilKillApp = 0;
static uint32_t __attribute__ ((naked, noinline)) sceLncUtilKillApp(uint32_t appid) {
	__asm__ volatile("jmp *f_sceLncUtilKillApp(%rip)");
}

static int init_needed_functions(void) {
	resolver_t resolver;
	uintptr_t libUserService = get_libSceUserService();

	if (libUserService == 0) {
		puts("failed to located libUserService");
		return -1;
	}

	uintptr_t libSystemService = get_libSceSystemService();

	if (libSystemService == 0) {
		puts("failed to located libSystemService");
		return -1;
	}

	uintptr_t user_service_meta = shared_lib_get_metadata(libUserService);
	uintptr_t user_service_imagebase = shared_lib_get_imagebase(libUserService);
	uintptr_t system_service_meta = shared_lib_get_metadata(libSystemService);
	uintptr_t system_service_imagebase = shared_lib_get_imagebase(libSystemService);

	resolver_init(&resolver);

	if (resolver_add_library_metadata(&resolver, user_service_imagebase, user_service_meta)) {
		puts("failed to add libUserService metadata to resolver");
		resolver_finalize(&resolver);
		return -1;
	}

	if (resolver_add_library_metadata(&resolver, system_service_imagebase, system_service_meta)) {
		puts("failed to add libSystemService metadata to resolver");
		resolver_finalize(&resolver);
		return -1;
	}

	int result = 0;

	f_sceUserServiceInitialize = LOOKUP_SYMBOL(&resolver, "sceUserServiceInitialize");
	if (f_sceUserServiceInitialize == 0) {
		puts("failed to resolve sceUserServiceInitialize");
		result = -1;
	}

	f_sceUserServiceGetForegroundUser = LOOKUP_SYMBOL(&resolver, "sceUserServiceGetForegroundUser");
	if (f_sceUserServiceGetForegroundUser == 0) {
		puts("failed to resolve sceUserServiceGetForegroundUser");
		result = -1;
	}

	f_sceLncUtilLaunchApp = LOOKUP_SYMBOL(&resolver, "sceLncUtilLaunchApp");
	if (f_sceLncUtilLaunchApp == 0) {
		puts("failed to resolve sceLncUtilLaunchApp");
		result = -1;
	}

	f_sceLncUtilKillApp = LOOKUP_SYMBOL(&resolver, "sceLncUtilKillApp");
	if (f_sceLncUtilKillApp == 0) {
		puts("failed to resolve sceLncUtilKillApp");
		result = -1;
	}

	resolver_finalize(&resolver);
	return result;
}

static bool launch_app(const char *titleId, uint32_t *appId) {
	puts("launching app");
	sceUserServiceInitialize(NULL);

	uint32_t id = -1;
	uint32_t res = sceUserServiceGetForegroundUser(&id);
	if (res != 0) {
		printf("sceUserServiceGetForegroundUser failed: 0x%llx\n", res);
		return false;
	}

	printf("user id %u\n", id);

	// the thread will clean this up
	struct LncAppParam param = {sizeof(struct LncAppParam), id, 0, 0, 0};

	puts("calling sceLncUtilLaunchApp");
	int err = sceLncUtilLaunchApp(titleId, NULL, &param);
	*appId = err;
	printf("sceLncUtilLaunchApp returned 0x%llx\n", (uint32_t)err);
	if (err >= 0) {
		return true;
	}
	switch((uint32_t) err) {
		case LNC_UTIL_ERROR_ALREADY_RUNNING:
			printf("app %s is already running\n", titleId);
			break;
		case LNC_ERROR_APP_NOT_FOUND:
			printf("app %s not found\n", titleId);
			break;
		default:
			printf("unknown error 0x%llx\n", (uint32_t) err);
			break;
	}
	return false;
}




typedef struct {
	uint8_t data[LOOB_BUILDER_SIZE];
} loop_builder_t;

// NOLINTBEGIN(readability-magic-numbers)

/*
static uint8_t SLEEP_LOOP[] = {
	// INT3
	0xcc,
	//	MOV RAX, usleep
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// MOV RDI, 4000000 // 4 seconds chosen by fair dice roll
	0x48, 0xc7, 0xc7, 0x00, 0x09, 0x3d, 0x00,
	// CALL RAX
	0xff, 0xd0,
	// INT3
	0xcc
};
*/

static void loop_builder_init(loop_builder_t *restrict self) {
	// FIXME
    volatile uint8_t *ptr = (volatile uint8_t *)self->data;
    ptr[0] = 0xcc;
    ptr[1] = 0x48;
    ptr[2] = 0xb8;
    ptr[11] = 0x48;
    ptr[12] = 0xc7;
    ptr[13] = 0xc7;
    ptr[14] = 0x00;
    ptr[15] = 0x09;
    ptr[16] = 0x3d;
    ptr[17] = 0x00;
    ptr[18] = 0xff;
    ptr[19] = 0xd0;
    ptr[20] = 0xcc;
    //memcpy(self->data, SLEEP_LOOP, LOOB_BUILDER_SIZE);
}

// NOLINTEND(readability-magic-numbers)

static void loop_builder_set_target(loop_builder_t *restrict self, uintptr_t addr) {
	*(uintptr_t *)(self->data + LOOP_BUILDER_TARGET_OFFSET) = addr;
}

static uintptr_t get_usleep_address(uintptr_t proc) {
	uintptr_t lib = proc_get_lib(proc, LIBKERNEL_HANDLE);
	if (lib == 0) {
		return 0;
	}

	return shared_lib_get_address(lib, USLEEP_NID);
}

bool touch_file(const char* destfile) {
	int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777); // NOLINT
	if (fd > 0) {
		close(fd);
		return true;
	}
	return false;
}


int network_listen(const char *soc_path) {
	unlink(soc_path);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		perror("[Spawner] Socket failed!");
		return -1;
	}

	struct sockaddr_un server;
	memset(&server, 0, sizeof(server));
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, soc_path, sizeof(server.sun_path) - 1);

	int r = bind(s, (struct sockaddr *)(&server), SUN_LEN(&server));
	if (r < 0) {
		printf("[Spawner] Bind failed! %s Path %s\n", strerror(errno), server.sun_path); // NOLINT(concurrency-mt-unsafe)
		return -1;
	}

	printf("Socket has name %s\n", server.sun_path);

	r = listen(s, 1);
	if (r < 0) {
		printf("[Spawner] listen failed! %s\n", strerror(errno)); // NOLINT(concurrency-mt-unsafe)
		return -1;
	}

	printf("touching %s\n", "/system_tmp/IPC");
	touch_file("/system_tmp/IPC");
	printf("network listen unix socket %d\n", s);
	return s;
}

typedef struct {
	const char *path;
	int fd;
	int conn;
} ipc_socket_t;

static ipc_socket_t g_ipc_socket = (ipc_socket_t) {
	.path = NULL,
	.fd = -1,
	.conn = -1
};

static void ipc_socket_close(ipc_socket_t *restrict self) {
	puts("ipc_socket_close");
	if (self->conn != -1) {
		close(self->conn);
		self->conn = -1;
	}
	if (self->fd != -1) {
		close(self->fd);
		self->fd = -1;
	}
	if (self->path != NULL) {
		unlink(self->path);
		self->path = NULL;
	}
}

static void shutdown_ipc(void) {
	if (g_ipc_socket.path != NULL) {
		ipc_socket_close(&g_ipc_socket);
	}
}

static void ipc_socket_open(ipc_socket_t *restrict self, const char *path) {
	self->path = path;
	self->fd = network_listen(path);
}

static bool is_process_alive(int pid) {
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
	return sysctl(mib, 4, NULL, NULL, NULL, 0) == 0;
}

typedef struct {
	int cmd;
	int pid;
	uintptr_t func;
} ipc_result_t;

static void *hook_thread(void *args) {
	uintptr_t *restrict spawned = (uintptr_t *)args;
	printf("hook thread started\n");

	ipc_socket_open(&g_ipc_socket, "/system_tmp/IPC");
	if (g_ipc_socket.fd == -1) {
		puts("ipc_socket_open failed");
		return NULL;
	}

	printf("listen done, fd: %d\n", g_ipc_socket.fd);

	g_ipc_socket.conn = accept(g_ipc_socket.fd, NULL, NULL);
	if (g_ipc_socket.conn == -1) {
		puts("accept failed");
		ipc_socket_close(&g_ipc_socket);
		return NULL;
	}

	puts("cli accepted");

	ipc_result_t res;
	if (_read(g_ipc_socket.conn, &res, sizeof(res)) == -1) {
		puts("read failed");
		ipc_socket_close(&g_ipc_socket);
		return NULL;
	}

	if (res.cmd != PROCESS_LAUNCHED) {
		puts("not launched");
		ipc_socket_close(&g_ipc_socket);
		return NULL;
	}

	puts("next");

	// close it so it can be opened in the spawned daemon
	ipc_socket_close(&g_ipc_socket);

	loop_builder_t loop;
	loop_builder_init(&loop);
	const int pid = res.pid;

	tracer_t tracer;
	if (tracer_init(&tracer, pid) < 0) {
		puts("tracer init failed");
		return NULL;
	}

	reg_t regs;
	if (tracer_get_registers(&tracer, &regs)) {
		puts("failed to get registers");
		tracer_finalize(&tracer);
		return NULL;
	}

	regs.r_rip = (register_t) res.func;
	printf("setting rip to 0x%08llx\n", res.func);
	if (tracer_set_registers(&tracer, &regs)) {
		puts("failed to set registers");
		tracer_finalize(&tracer);
		return NULL;
	}

	puts("running until execve completes");

	// run until execve completion
	int state = tracer_continue(&tracer, true);

	if (!WIFSTOPPED(state)) {
		puts("process not stopped");
		tracer_finalize(&tracer);
		return NULL;
	}

	if (WSTOPSIG(state) != SIGTRAP) {
		printf("process received signal %d but SIGTRAP was expected\n", WSTOPSIG(state));
		if (tracer_get_registers(&tracer, &regs)) {
			puts("failed to get registers");
		} else {
			tracer_dump_registers(&regs);
		}

		tracer_finalize(&tracer);
		return NULL;
	}

	puts("execve completed");

	//printf("tracer_continue after execve returned state 0x%x\n", state);
	//dump_state(state);

	do { // NOLINT
		*spawned = get_proc(pid);
		if (*spawned == 0) {
			if (!is_process_alive(pid)) {
				puts("process died");
				tracer_finalize(&tracer);
				return NULL;
			}
		}
	} while (*spawned == 0);

	uintptr_t libkernel = proc_get_lib(*spawned, LIBKERNEL_HANDLE);
	uintptr_t base = shared_lib_get_imagebase(libkernel);

	printf("libkernel imagebase: 0x%08llx\n", base);

	puts("spawned process obtained");

	puts("success");

	// FIXME why did getting the nanosleep offset from *spawned crash
	const uintptr_t usleep_address = get_usleep_address(*spawned);

	loop_builder_set_target(&loop, usleep_address);
	uintptr_t eboot = proc_get_eboot(*spawned);
	base = shared_lib_get_imagebase(eboot);

	printf("process imagebase 0x%08llx\n", base);

	puts("patching entrypoint");

	// force the entrypoint to an infinite loop so that it doesn't start until we're ready
	userland_copyin(pid, loop.data, base + ENTRYPOINT_OFFSET, sizeof(loop.data));

	puts("entrypoint patched");

	puts("finishing process loading");

	state = tracer_continue(&tracer, true);

	if (!WIFSTOPPED(state)) {
		puts("process not stopped");
		tracer_finalize(&tracer);
		return NULL;
	}

	if (WSTOPSIG(state) != SIGTRAP) {
		printf("process received signal %d but SIGTRAP was expected\n", WSTOPSIG(state));
		tracer_finalize(&tracer);
		return NULL;
	}

	tracer_get_registers(&tracer, &regs);

	if ((uintptr_t)regs.r_rip != (base + ENTRYPOINT_OFFSET + 1)) {
		puts("unexpected rip value, something went wrong");
	} else {
		puts("process loaded successfully");
	}

	puts("finished");
	printf("spawned imagebase 0x%08llx\n", base);

	tracer_finalize(&tracer);
	return NULL;
}

static void kill_loading_app(void) {
	if (gAppId != 0) {
		sceLncUtilKillApp(gAppId);
		gAppId = 0;
	}
}

static void cleanup(void) {
	kill_loading_app();
	shutdown_ipc();
}


extern int main(void) {
	//Stdout dummy{};
	//ptrace(PT_ATTACH, pid, 0, 0);
	///clearFramePointer();
	puts("main entered");
	if (has_unprocessed_relocations()) {
		puts("fixing unprocessed relocations for spawner.elf");
		process_relocations();
	}

	fault_handler_init(cleanup);

	init_needed_functions();

	if (!make_homebrew_app()) {
		return 0;
	}

	uint8_t qaflags[QAFLAGS_SIZE];
	kernel_copyout(kernel_base + get_qa_flags_offset(), qaflags, QAFLAGS_SIZE);
	qaflags[1] |= 1 | 2;
	kernel_copyin(qaflags, kernel_base + get_qa_flags_offset(), QAFLAGS_SIZE);

	patch_syscore();

	//puts("spawning daemon");

	pthread_t td = NULL;
	uintptr_t spawned = 0;
	pthread_create(&td, NULL, hook_thread, &spawned);

	if (!launch_app(APP_TITLE_ID, &gAppId)) {
		// we're screwed
		return 0;
	}

	// the thread should have already completed
	pthread_join(td, NULL);

	if (spawned == 0 || !load(spawned)) {
		puts("failed to load elf into new process");
		sceLncUtilKillApp(gAppId);
		gAppId = 0;
		return 0;
	}

	return 0;
}
