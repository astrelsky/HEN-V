#include "msg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static sigjmp_buf message_sender_buf;
static sigjmp_buf message_receiver_buf;

static const struct event_thread_vtable g_message_send_event_thread_vtable;
static const struct event_thread_vtable g_message_recv_event_thread_vtable;

typedef struct {
	event_thread_t base;
} message_send_event_thread_t;

typedef struct {
	event_thread_t base;
} message_recv_event_thread_t;

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
		switch (msg.msgType) {
			case BREW_MSG_TYPE_REGISTER_PREFIX_HANDLER: // NOLINT
				// TODO
				break;
			case BREW_MSG_TYPE_REGISTER_LAUNCH_LISTENER:
				// TODO
				break;
			case BREW_MSG_TYPE_APP_LAUNCHED:
				// TODO
				break;
			case BREW_MSG_TYPE_KILL:
				event_thread_pool_kill(self->base.pool);
				break;
			default:
				printf("invalid message type 0x%08llx, message ignored\n", msg.msgType);
				continue;
		}
	}

	return NULL;
}

event_thread_t *message_send_event_thread_new(event_thread_pool_t *pool) {
	message_send_event_thread_t *self = malloc(sizeof(message_send_event_thread_t));
	if (self == NULL) {
		perror("message_send_event_thread_new");
		return NULL;
	}
	event_thread_init(&self->base, "MessageSendThread", pool, &message_sender_buf, message_sender);
	self->base._vptr = &g_message_send_event_thread_vtable;
	return &self->base;
}

event_thread_t *message_recv_event_thread_new(event_thread_pool_t *pool) {
	message_recv_event_thread_t *self = malloc(sizeof(message_recv_event_thread_t));
	if (self == NULL) {
		perror("message_recv_event_thread_new");
		return NULL;
	}
	event_thread_init(&self->base, "MessageReceiveThread", pool, &message_receiver_buf, message_receiver);
	self->base._vptr = &g_message_recv_event_thread_vtable;
	return &self->base;
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
