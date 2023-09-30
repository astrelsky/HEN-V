#include "chan.h"
#include "libs.h"
#include "proc.h"
#include "tracer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <unistd.h>

#define PING 0
#define PONG 1
#define PROCESS_LAUNCHED 1
#define LOOB_BUILDER_SIZE 21
#define LOOP_BUILDER_TARGET_OFFSET 3
#define USLEEP_NID "QcteRwbsnV0"
#define ENTRYPOINT_OFFSET 0x70

extern int _write(int fd, const void *, size_t); // NOLINT
extern ssize_t _read(int, void *, size_t); // NOLINT

typedef struct {
	uint8_t data[LOOB_BUILDER_SIZE];
} loop_builder_t;

// NOLINTBEGIN(readability-magic-numbers)

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

// NOLINTEND(readability-magic-numbers)

static void loop_builder_init(loop_builder_t *restrict self) {
	memcpy(self->data, SLEEP_LOOP, LOOB_BUILDER_SIZE);
}

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

static bool touch_file(const char* destfile) {
	int fd = open(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777); // NOLINT
	if (fd > 0) {
		close(fd);
		return true;
	}
	return false;
}

static int network_listen(const char *soc_path) {
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

// TODO close this on segfault or whatever signal
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


void *ipc_hook_thread(void *args) {
	chan_t *restrict elf_loader = (chan_t *)args;
	printf("hook thread started\n");

	ipc_socket_open(&g_ipc_socket, "/system_tmp/IPC");
	if (g_ipc_socket.fd == -1) {
		puts("ipc_socket_open failed");
		return NULL;
	}

	printf("listen done\n");

	g_ipc_socket.conn = accept(g_ipc_socket.fd, NULL, NULL);
	if (g_ipc_socket.conn == -1) {
		puts("accept failed");
		ipc_socket_close(&g_ipc_socket);
		return NULL;
	}

	puts("cli accepted");

	while (true) {

		ipc_result_t res;
		if (_read(g_ipc_socket.conn, &res, sizeof(res)) == -1) {
			puts("read failed");
			ipc_socket_close(&g_ipc_socket);
			return NULL;
		}

		if (res.cmd == PING) {
			puts("ping received");
			int reply = PONG;
			if (_write(g_ipc_socket.conn, &reply, sizeof(reply)) == -1) {
				puts("write failed");
				ipc_socket_close(&g_ipc_socket);
				return NULL;
			}
			if (_read(g_ipc_socket.conn, &res, sizeof(res)) == -1) {
				puts("read failed");
				ipc_socket_close(&g_ipc_socket);
				return NULL;
			}
		}

		if (res.cmd != PROCESS_LAUNCHED) {
			puts("not launched");
			ipc_socket_close(&g_ipc_socket);
			return NULL;
		}

		puts("next");

		if (res.func == 0) {
			// this is only a notification that an app has launched, no elf loading
			return NULL;
		}

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
			tracer_finalize(&tracer);
			return NULL;
		}

		puts("execve completed");

		//printf("tracer_continue after execve returned state 0x%x\n", state);
		//dump_state(state);

		uintptr_t spawned = 0;
		do { // NOLINT
			spawned = get_proc(pid);
			if (spawned == 0) {
				if (!is_process_alive(pid)) {
					puts("process died");
					tracer_finalize(&tracer);
					return NULL;
				}
			}
		} while (spawned == 0);

		uintptr_t libkernel = proc_get_lib(spawned, LIBKERNEL_HANDLE);
		uintptr_t base = shared_lib_get_imagebase(libkernel);

		printf("libkernel imagebase: 0x%08llx\n", base);

		puts("spawned process obtained");

		puts("success");

		// FIXME why did getting the nanosleep offset from *spawned crash
		const uintptr_t usleep_address = get_usleep_address(spawned);

		loop_builder_set_target(&loop, usleep_address);
		uintptr_t eboot = proc_get_eboot(spawned);
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

		// load elf in the elf loading thread
		// get the elf loading channel from thread args
		chan_send_int(elf_loader, res.pid);
	}

	return NULL;
}
