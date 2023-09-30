#include "chan.h"
#include "elfldr.h"
#include "module.h"
#include "msg.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/_pthreadtypes.h>
#include <sys/stat.h>
#include <unistd.h>

extern void *ipc_hook_thread(void *args);

// this is large enough that the channels shouldn't block when being written to
#define DEFAULT_CHANNEL_CAPACITY 16

#define PATH_APPEND(path, fname) memcpy(path, fname, strlen(fname))

//extern int _sceApplicationGetAppId(int pid, uint32_t *appid); // NOLINT
//extern int sceLncUtilGetAppTitleId(uint32_t appid, char *tid); // NOLINT

typedef struct {
	size_t length;
	void *msg;
} small_msg_t;

typedef struct {
	chan_t *channel;
} thread_args_t;

typedef struct {
	chan_t *send_channel;
	// include all other channels as well
} recv_thread_args_t;

static chan_t *buffered_chan_init(void) {
	return chan_init(DEFAULT_CHANNEL_CAPACITY);
}

static void message_sender(chan_t *restrict channel) {
	while (true) {
		void *data = NULL;
		if (chan_recv(channel, &data) == -1) {
			if (errno == EPIPE) {
				break;
			}
			perror("chan_recv failed");
			continue;
		}
	}
}

static void *message_send_thread(void *p_args) {
	thread_args_t *args = (thread_args_t *)p_args;
	message_sender(args->channel);
	return NULL;
}

static void dummy(int _) {
	(void) _;
}

static void *message_recv_thread(void *args) {
	(void) args;
	signal(SIGUSR1, dummy);

	app_message_t msg;

	while (true) {
		if (sceAppMessagingReceiveMsg(&msg) < 0) {
			puts("sceAppMessagingReceiveMsg failed");
			continue;
		}
	}

	return NULL;
}

static bool load_elf(int pid) {
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

	printf("opening %s\n", info.sandboxed_path);

	int fd = open(info.sandboxed_path, O_RDONLY);
	if (fd == -1) {
		perror("load_elf open");
		return false;
	}

	if (read(fd, buf, st.st_size) != st.st_size) {
		perror("read failed");
		return false;
	}

	if (!run_elf(buf, pid)) {
		puts("run_elf failed");
		return false;
	}
	return true;
}

static void *elf_load_thread(void *p_args) {
	thread_args_t *args = (thread_args_t *)p_args;

	int pid = 0;
	while (chan_recv_int32(args->channel, &pid) == 0) {
		if (!load_elf(pid)) {
			puts("failed to load elf");
		}
	}
	return NULL;
}

int main(void) {

	pthread_t send_thread = NULL;
	thread_args_t send_args = {
		.channel = buffered_chan_init()
	};
	pthread_create(&send_thread, NULL, message_send_thread, &send_args);

	pthread_t recv_thread = NULL;
	recv_thread_args_t recv_args = {
		.send_channel = send_args.channel
	};
	pthread_create(&recv_thread, NULL, message_recv_thread, &recv_args);

	pthread_t elf_thread = NULL;
	thread_args_t elf_args = {
		.channel = buffered_chan_init()
	};
	pthread_create(&elf_thread, NULL, elf_load_thread, &elf_args);

	pthread_t ipc_thread = NULL;
	pthread_create(&ipc_thread, NULL, ipc_hook_thread, elf_args.channel);

	pthread_join(send_thread, NULL);

	chan_close(elf_args.channel);

	// at this point all channels are closed
	// kick the recv thread to unblock
	// sceAppMessagingReceiveMsg and gracefully finish
	pthread_kill(recv_thread, SIGUSR1);
	pthread_kill(elf_thread, SIGUSR1);
	pthread_join(elf_thread, NULL);
	pthread_join(recv_thread, NULL);

	return 0;
}
