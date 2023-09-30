#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <sys/signal.h>

#include "chan.h"
#include "msg.h"

#define TRUE 1
#define FALSE 0

// this is large enough that the channels shouldn't block when being written to
#define DEFAULT_CHANNEL_CAPACITY 16

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
	while (TRUE) {
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

	while (TRUE) {
		if (sceAppMessagingReceiveMsg(&msg) < 0) {
			puts("sceAppMessagingReceiveMsg failed");
			continue;
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

	pthread_join(send_thread, NULL);

	// at this point all channels are closed
	// kick the recv thread to unblock
	// sceAppMessagingReceiveMsg and gracefully finish
	pthread_kill(recv_thread, SIGUSR1);
	pthread_join(recv_thread, NULL);

	return 0;
}
