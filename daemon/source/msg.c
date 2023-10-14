#include "msg.h"
#include "chan.h"
#include "set.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

extern int _sceApplicationGetAppId(uint32_t pid, uint32_t *appid); // NOLINT

static sigjmp_buf message_sender_buf;
static sigjmp_buf message_receiver_buf;

static const struct event_thread_vtable g_message_send_event_thread_vtable;
static const struct event_thread_vtable g_message_recv_event_thread_vtable;

typedef struct {
	uint32_t appId;
	uint32_t msgType;
	size_t msgLength;
	uint32_t flags;
	uint8_t msg[];
} msg_args_t;

typedef struct message_send_event_thread_t {
	event_thread_t base;
	_Atomic(msg_args_t *) msg;
} message_send_event_thread_t;

typedef struct {
	event_thread_t base;

	// NOTE: the handling of these is fast and may occur in this thread
	_Atomic(set_uint_t *) listeners;
} message_recv_event_thread_t;

static uint32_t get_app_id(uint32_t pid) {
	uint32_t appid = 0;
	_sceApplicationGetAppId(pid, &appid);
	return appid;
}

// TODO: this can probably go away if sceAppMessagingSendMsg is non-blocking
static void *message_sender(message_send_event_thread_t *self) {
	while (true) {
		msg_args_t *restrict msg = self->msg;
		if (chan_recv(self->base.channel, (void *)msg) == -1) {
			if (errno == EPIPE) {
				break;
			}
			perror("chan_recv failed");
			continue;
		}
		atomic_store(&self->msg, msg);
		sceAppMessagingSendMsg(msg->appId, msg->msgType, msg->msg, msg->msgLength, msg->flags);
		free(atomic_exchange(&self->msg, NULL));
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
			case BREW_MSG_TYPE_REGISTER_PREFIX_HANDLER:
				// TODO
				break;
			case BREW_MSG_TYPE_REGISTER_LAUNCH_LISTENER:
				set_uint_add(self->listeners, *(unsigned int *)msg.payload);
				break;
			case BREW_MSG_TYPE_UNREGISTER_PREFIX_HANDLER:
				// TODO
				break;
			case BREW_MSG_TYPE_UNREGISTER_LAUNCH_LISTENER:
				// TODO
				set_uint_remove(self->listeners, get_app_id(msg.sender));
				break;
			case BREW_MSG_TYPE_APP_LAUNCHED: {
				const unsigned int *restrict end = self->listeners->last;
				for (const unsigned int *restrict it = self->listeners->first; it != end; it++) {

				}
			}
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

static void message_recv_event_thread_init(message_recv_event_thread_t *self, event_thread_pool_t *pool) {
	event_thread_init(&self->base, "MessageReceiveThread", pool, &message_receiver_buf, message_receiver);
	self->base._vptr = &g_message_recv_event_thread_vtable;
	atomic_init(&self->listeners, NULL);
	atomic_exchange(&self->listeners, set_uint_new());
}

static void message_recv_event_thread_finalize(message_recv_event_thread_t *self) {
	event_thread_finalize(&self->base);
	set_uint_delete(atomic_exchange(&self->listeners, NULL));
}

static void message_recv_event_thread_reset(message_recv_event_thread_t *self) {
	event_thread_reset(&self->base);
	set_uint_t *listeners = atomic_load(&self->listeners);
	if (listeners != NULL) {
		set_uint_clear(listeners);
	}
}

int message_send_event_thread_send_message(message_send_event_thread_t *self, uint32_t appId, uint32_t msgType, const void *msg, size_t msgLength, uint32_t flags) {
	msg_args_t *args = malloc(sizeof(msg_args_t) + msgLength);
	if (args == NULL) {
		errno = ENOMEM;
		return -1;
	}
	*args = (msg_args_t) {
		.appId = appId,
		.msgType = msgType,
		.msgLength = msgLength,
		.flags = flags
	};
	memcpy(args->msg, msg, msgLength);
	return chan_send(self->base.channel, args);
}

message_send_event_thread_t *message_send_event_thread_new(event_thread_pool_t *pool) {
	message_send_event_thread_t *self = malloc(sizeof(message_send_event_thread_t));
	if (self == NULL) {
		perror("message_send_event_thread_new");
		return NULL;
	}
	event_thread_init(&self->base, "MessageSendThread", pool, &message_sender_buf, message_sender);
	self->base._vptr = &g_message_send_event_thread_vtable;
	return self;
}

static void message_send_event_thread_finalize(message_send_event_thread_t *self) {
	event_thread_finalize(&self->base);
	free(atomic_exchange(&self->msg, NULL));
}

static void message_send_event_thread_reset(message_send_event_thread_t *self) {
	event_thread_reset(&self->base);
	free(atomic_exchange(&self->msg, NULL));
}

event_thread_t *message_recv_event_thread_new(event_thread_pool_t *pool) {
	message_recv_event_thread_t *self = malloc(sizeof(message_recv_event_thread_t));
	if (self == NULL) {
		perror("message_recv_event_thread_new");
		return NULL;
	}
	message_recv_event_thread_init(self, pool);
	return &self->base;
}

// these don't hold anything that need to be cleaned up and the defaults are acceptable

static const struct event_thread_vtable g_message_send_event_thread_vtable = {
	.finalize = message_send_event_thread_finalize,
	.reset = message_send_event_thread_reset,
};

static const struct event_thread_vtable g_message_recv_event_thread_vtable = {
	.finalize = message_recv_event_thread_finalize,
	.reset = message_recv_event_thread_reset,
};
