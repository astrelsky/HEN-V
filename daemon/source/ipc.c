#include "chan.h"
#include "ipc.h"
#include "elfldr.h"
#include "libs.h"
#include "module.h"
#include "proc.h"
#include "tracer.h"

#include <errno.h>
#include <fcntl.h>
#include <machine/setjmp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#define PATH_APPEND(path, fname) memcpy(path, fname, strlen(fname))

static const struct event_thread_vtable g_ipc_event_thread_vtable;
static sigjmp_buf ipc_jmpbuf;

static const struct event_thread_vtable g_elfldr_thread_vtable;
static sigjmp_buf elfldr_jmpbuf;

typedef struct {
	int cmd;
	int pid;
	uintptr_t func;
} ipc_result_t;

typedef struct {
	tracer_t tracer;
	uintptr_t func;
} prep_process_args_t;

typedef struct {
	event_thread_t base;
	_Atomic(tracer_t *) tracer;
	_Atomic(uint8_t *) elfbuf;
	_Atomic(elf_loader_t *) elfldr;
} elfldr_event_thread_t;

typedef struct {
	_Atomic(const char *) path;
	atomic_int fd;
	atomic_int conn;
} ipc_socket_t;

typedef struct {
	event_thread_t base;
	ipc_socket_t socket;
	_Atomic(tracer_t *) tracer;
} ipc_event_thread_t;

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

static int tracer_delete(tracer_t *self) {
	if (self == NULL) {
		return 0;
	}
	int res = tracer_finalize(self);
	free(self);
	return res;
}

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

static void ipc_socket_close(ipc_socket_t *restrict self) {
	puts("ipc_socket_close");
	if (atomic_load(&self->conn) != -1) {
		close(atomic_exchange(&self->conn, -1));
	}
	if (atomic_load(&self->fd) != -1) {
		close(atomic_exchange(&self->fd, -1));
	}
	if (atomic_load(&self->path) != NULL) {
		unlink(atomic_exchange(&self->path, NULL));
	}
}

static void ipc_socket_open(ipc_socket_t *restrict self, const char *path) {
	atomic_store(&self->path, path);
	atomic_store(&self->fd, network_listen(path));
}

static bool is_process_alive(int pid) {
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
	return sysctl(mib, 4, NULL, NULL, NULL, 0) == 0;
}

static int handle_app_launch(ipc_event_thread_t *self) {
	ipc_result_t res;
	if (_read(self->socket.conn, &res, sizeof(res)) == -1) {
		puts("read failed");
		return 0;
	}

	if (res.cmd == PING) {
		puts("ping received");
		int reply = PONG;
		if (_write(self->socket.conn, &reply, sizeof(reply)) == -1) {
			puts("write failed");
			return 0;
		}
		if (_read(self->socket.conn, &res, sizeof(res)) == -1) {
			puts("read failed");
			return 0;
		}
	}

	if (res.cmd != PROCESS_LAUNCHED) {
		puts("not launched");
		return 0;
	}

	puts("next");

	if (res.func == 0) {
		// this is only a notification that an app has launched, no elf loading
		return 0;
	}

	const int pid = res.pid;

	prep_process_args_t *args = malloc(sizeof(prep_process_args_t));
	if (args == NULL) {
		perror("impossible");
		return 0;
	}

	atomic_store(&self->tracer, (tracer_t *)args);
	args->func = res.func;
	int state = tracer_init(self->tracer, pid);
	if (state < 0) {
		puts("tracer init failed");
		return -1;
	}

	if (!WIFSTOPPED(state)) {
		puts("process not stopped");
		return -1;
	}

	// TODO: yeet this to the elf loading thread

	return 1;
}

static bool prepare_new_process(elfldr_event_thread_t *self, uintptr_t func) {
	tracer_t *tracer = self->tracer;

	reg_t regs;
	if (tracer_get_registers(tracer, &regs)) {
		puts("failed to get registers");
		return false;
	}

	regs.r_rip = (register_t) func;
	printf("setting rip to 0x%08llx\n", func);
	if (tracer_set_registers(tracer, &regs)) {
		puts("failed to set registers");
		return false;
	}

	puts("running until execve completes");

	// run until execve completion
	int state = tracer_continue(tracer, true);

	if (!WIFSTOPPED(state)) {
		puts("process not stopped");
		return false;
	}

	if (WSTOPSIG(state) != SIGTRAP) {
		printf("process received signal %d but SIGTRAP was expected\n", WSTOPSIG(state));
		return false;
	}

	puts("execve completed");

	//printf("tracer_continue after execve returned state 0x%x\n", state);
	//dump_state(state);

	uintptr_t spawned = 0;
	do { // NOLINT
		spawned = get_proc(tracer->pid);
		if (spawned == 0) {
			if (!is_process_alive(tracer->pid)) {
				puts("process died");
				return false;
			}
		}
	} while (spawned == 0);

	uintptr_t libkernel = proc_get_lib(spawned, LIBKERNEL_HANDLE);
	uintptr_t base = shared_lib_get_imagebase(libkernel);

	printf("libkernel imagebase: 0x%08llx\n", base);

	puts("spawned process obtained");

	puts("success");

	const uintptr_t usleep_address = get_usleep_address(spawned);

	loop_builder_t loop;
	loop_builder_init(&loop);
	loop_builder_set_target(&loop, usleep_address);
	uintptr_t eboot = proc_get_eboot(spawned);
	base = shared_lib_get_imagebase(eboot);

	printf("process imagebase 0x%08llx\n", base);

	puts("patching entrypoint");

	// force the entrypoint to an infinite loop so that it doesn't start until we're ready
	userland_copyin(tracer->pid, loop.data, base + ENTRYPOINT_OFFSET, sizeof(loop.data));

	puts("entrypoint patched");

	puts("finishing process loading");

	state = tracer_continue(tracer, true);

	if (!WIFSTOPPED(state)) {
		puts("process not stopped");
		return false;
	}

	if (WSTOPSIG(state) != SIGTRAP) {
		printf("process received signal %d but SIGTRAP was expected\n", WSTOPSIG(state));
		return false;
	}

	tracer_get_registers(tracer, &regs);

	if ((uintptr_t)regs.r_rip != (base + ENTRYPOINT_OFFSET + 1)) {
		puts("unexpected rip value, something went wrong");
	} else {
		puts("process loaded successfully");
	}

	puts("finished");
	printf("spawned imagebase 0x%08llx\n", base);

	return true;
}

void *ipc_hook_thread(ipc_event_thread_t *self) {
	printf("hook thread started\n");

	ipc_socket_open(&self->socket, "/system_tmp/IPC");
	if (self->socket.fd == -1) {
		puts("ipc_socket_open failed");
		return NULL;
	}

	puts("listen done");

	atomic_store(&self->socket.conn, accept(self->socket.fd, NULL, NULL));
	if (self->socket.conn == -1) {
		puts("accept failed");
		ipc_socket_close(&self->socket);
		return NULL;
	}

	puts("cli accepted");

	while (true) {
		int state = handle_app_launch(self);
		if (state == 0) {
			// ignorable error occured
			continue;
		}

		if (state == -1) {
			// error occured and we need to free resources
			tracer_delete(atomic_exchange(&self->tracer, NULL));
			continue;
		}

		event_thread_t *ldr = event_thread_pool_get_elfldr_thread(self->base.pool);

		// pass ownership of the tracer to the elfldr
		chan_send(ldr->channel, atomic_exchange(&self->tracer, NULL));
	}

	return NULL;
}

static bool load_elf(elfldr_event_thread_t *self, int pid) {
	static module_info_t info;
	if (get_module_info(pid, 0, &info) != 0) {
		puts("get_module_info failed");
		return false;
	}

	char *path = strrchr(info.sandboxed_path, '/');
	if (path == NULL) {
		printf("sandboxed path contains no folders? %s\n", info.sandboxed_path);
		return false;
	}

	PATH_APPEND(path, "homebrew.elf");

	struct stat st;
	if (stat(info.sandboxed_path, &st) < 0) {
		perror("load_elf stat");
		return false;
	}

	void *buf = malloc(st.st_size);
	if (buf == NULL) {
		perror("load_elf impossible");
		return false;
	}

	atomic_store(&self->elfbuf, buf);

	printf("opening %s\n", info.sandboxed_path);

	int fd = open(info.sandboxed_path, O_RDONLY);
	if (fd == -1) {
		perror("load_elf open");
		free(atomic_exchange(&self->elfbuf, NULL));
		return false;
	}

	// if a fault occurs between here and close I should just quit

	if (read(fd, buf, st.st_size) != st.st_size) {
		perror("load_elf read failed");
		free(atomic_exchange(&self->elfbuf, NULL));
		close(fd);
		return false;
	}

	close(fd);

	elf_loader_t *elfldr = elf_loader_create(atomic_exchange(&self->elfbuf, NULL), pid);
	atomic_store(&self->elfldr, elfldr);

	if (elfldr == NULL) {
		perror("load_elf impossible");
		return false;
	}

	bool result = true;
	if (!elf_loader_run(self->elfldr)) {
		puts("load_elf run_elf failed");
		result = false;
	}

	elf_loader_finalize(atomic_exchange(&self->elfldr, NULL));
	return result;
}

static void *load_elf_thread(elfldr_event_thread_t *self) {
	prep_process_args_t *args = NULL;
	while (chan_recv(self->base.channel, (void **)&args) == 0) {
		const int pid = args->tracer.pid;
		atomic_store(&self->tracer, (tracer_t *)args);
		bool ok = prepare_new_process(self, args->func);
		tracer_delete(atomic_exchange(&self->tracer, NULL));
		if (ok) {
			if (!load_elf(self, pid)) {
				printf("failed to load elf for pid %d\n", pid);
			}
		}
	}
	return NULL;
}

event_thread_t *ipc_event_thread_new(event_thread_pool_t *pool) {
	ipc_event_thread_t *self = malloc(sizeof(ipc_event_thread_t));
	if (self == NULL) {
		perror("ipc_event_thread_new");
		return NULL;
	}

	event_thread_init(&self->base, "SyscoreIpcThread", pool, &ipc_jmpbuf, ipc_hook_thread);
	self->base._vptr = &g_ipc_event_thread_vtable;
	atomic_init(&self->socket.path, NULL);
	atomic_init(&self->socket.fd, -1);
	atomic_init(&self->socket.conn, -1);
	atomic_init(&self->tracer, NULL);

	return &self->base;
}

static void ipc_event_thread_reset(ipc_event_thread_t *self) {
	// close this first since it is more important
	ipc_socket_close(&self->socket);

	tracer_delete(atomic_exchange(&self->tracer, NULL));
}

static void ipc_event_thread_finalize(ipc_event_thread_t *self) {
	// close this first since it is more important
	ipc_socket_close(&self->socket);

	event_thread_finalize(&self->base);

	// we shouldn't have one during normal finalization but do it anyway
	tracer_delete(atomic_exchange(&self->tracer, NULL));
}

event_thread_t *elfldr_event_thread_new(event_thread_pool_t *pool) {
	elfldr_event_thread_t *self = malloc(sizeof(elfldr_event_thread_t));
	if (self == NULL) {
		perror("elfldr_event_thread_new");
		return NULL;
	}

	event_thread_init(&self->base, "HenVElfLoaderThread", pool, &elfldr_jmpbuf, load_elf_thread);
	self->base._vptr = &g_elfldr_thread_vtable;
	atomic_init(&self->elfldr, NULL);
	atomic_init(&self->elfbuf, NULL);
	atomic_init(&self->tracer, NULL);

	return &self->base;
}

static void elfldr_event_thread_reset(elfldr_event_thread_t *self) {
	elf_loader_delete(atomic_exchange(&self->elfldr, NULL));
	tracer_delete(atomic_exchange(&self->tracer, NULL));
	free(atomic_exchange(&self->elfbuf, NULL));
}

static void elfldr_event_thread_finalize(elfldr_event_thread_t *self) {
	elf_loader_delete(atomic_exchange(&self->elfldr, NULL));
	self->elfldr = NULL;
	event_thread_finalize(&self->base);
}

static const struct event_thread_vtable g_ipc_event_thread_vtable = {
	.finalize = ipc_event_thread_finalize,
	.reset = ipc_event_thread_reset,
};

static const struct event_thread_vtable g_elfldr_thread_vtable = {
	.finalize = elfldr_event_thread_finalize,
	.reset = elfldr_event_thread_reset,
};
