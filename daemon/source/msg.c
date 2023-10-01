#include "msg.h"

#include <errno.h>
#include <stdio.h>

static sigjmp_buf message_sender_buf;
static sigjmp_buf message_receiver_buf;

static const struct event_thread_vtable g_message_send_event_thread_vtable;
static const struct event_thread_vtable g_message_recv_event_thread_vtable;

static void *message_sender(message_send_event_thread_t *self) {
	while (true) {
		void *data = NULL;
		if (chan_recv(self->base.channel, &data) == -1) {
			if (errno == EPIPE) {
				break;
			}
			perror("chan_recv failed");
			continue;
		}
	}
	return NULL;
}

static void *message_receiver(message_recv_event_thread_t *self) {

	// TODO: this is going to need access to the other channels

	(void) self;
	app_message_t msg;

	while (true) {
		if (sceAppMessagingReceiveMsg(&msg) < 0) {
			puts("sceAppMessagingReceiveMsg failed");
			continue;
		}
	}

	return NULL;
}

void message_send_event_thread_init(message_send_event_thread_t *self) {
	event_thread_init(&self->base, "MessageSendThread", &message_sender_buf, message_sender);
	self->base._vptr = &g_message_send_event_thread_vtable;
}

void message_recv_event_thread_init(message_recv_event_thread_t *self) {
	event_thread_init(&self->base, "MessageReceiveThread", &message_receiver_buf, message_receiver);
	self->base._vptr = &g_message_recv_event_thread_vtable;
}

// these don't hold anything that need to be cleaned up and the defaults are acceptable

static const struct event_thread_vtable g_message_send_event_thread_vtable = {
	.finalize = event_thread_finalize,
	.reset = event_thread_reset,
};

static const struct event_thread_vtable g_message_recv_event_thread_vtable = {
	.finalize = event_thread_finalize,
	.reset = event_thread_reset,
};
