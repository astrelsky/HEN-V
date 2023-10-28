#include "chan.h"
#include "ipc.h"
#include "msg.h"
#include "notification.h"
#include "pool.h"

#include <stdlib.h>
#include <stdio.h>

typedef struct event_thread_pool {
	event_thread_t *ipc;
	event_thread_t *elfldr;
	message_send_event_thread_t *msg_send;
	event_thread_t *msg_recv;
	notif_send_event_thread_t *notif;
	chan_t *done;
} event_thread_pool_t;

static void *delete_event_thread(void *self) {
	if (self != NULL) {
		((event_thread_t *)self)->_vptr->finalize(self);
	}
	return NULL;
}

static void start_event_thread(void *self) {
	if (self != NULL) {
		event_thread_start((event_thread_t *)self);
	}
}

static void close_event_thread(void *self) {
	if (self != NULL) {
		event_thread_close((event_thread_t *)self);
	}
}

static void start_event_join(void *self) {
	if (self != NULL) {
		event_thread_join((event_thread_t *)self);
	}
}

event_thread_pool_t *event_thread_pool_new(void) {
	event_thread_pool_t *self = malloc(sizeof(event_thread_pool_t));
	if (self == NULL) {
		perror("event_thread_pool_new");
		return NULL;
	}

	*self = (event_thread_pool_t) {
		.ipc = ipc_event_thread_new(self),
		.elfldr = elfldr_event_thread_new(self),
		.msg_send = message_send_event_thread_new(self),
		.msg_recv = message_recv_event_thread_new(self),
		.notif = notif_send_event_thread_new(self),
		.done = chan_init(0) // unbuffered
	};

	return self;
}

void event_thread_pool_delete(event_thread_pool_t *self) {
	if (self == NULL) {
		return;
	}

	self->ipc = delete_event_thread(self->ipc);
	self->elfldr = delete_event_thread(self->elfldr);
	self->msg_send = delete_event_thread(self->msg_send);
	self->msg_recv = delete_event_thread(self->msg_recv);
	self->notif = delete_event_thread(self->notif);
	chan_dispose(self->done);

	free(self);
}

event_thread_t *event_thread_pool_get_ipc_thread(event_thread_pool_t *self) {
	return self->ipc;
}

event_thread_t *event_thread_pool_get_elfldr_thread(event_thread_pool_t *self) {
	return self->elfldr;
}

void event_thread_pool_start(event_thread_pool_t *self) {
	start_event_thread(self->ipc);
	start_event_thread(self->elfldr);
	start_event_thread(self->msg_send);
	start_event_thread(self->msg_recv);
	start_event_thread(self->notif);
}

void event_thread_pool_wait(event_thread_pool_t *self) {
	int done = 0;
	chan_recv_int(self->done, &done);
}

void event_thread_pool_join(event_thread_pool_t *self) {
	close_event_thread(self->ipc);
	close_event_thread(self->elfldr);
	close_event_thread(self->msg_send);
	close_event_thread(self->msg_recv);
	close_event_thread(self->notif);

	start_event_join(self->ipc);
	start_event_join(self->elfldr);
	start_event_join(self->msg_send);
	start_event_join(self->msg_recv);
	start_event_join(self->notif);
}

void event_thread_pool_kill(event_thread_pool_t *self) {
	chan_send_int(self->done, 1);
}

int event_thread_pool_send_notification(event_thread_pool_t *self, const char *msg, ...) {
	va_list arg;
	va_start(arg, msg);
	int err = notif_send_event_thread_vprintf(self->notif, msg, arg);
	va_end(arg);
	return err;
}

int event_thread_pool_send_message(event_thread_pool_t *self, uint32_t appId, uint32_t msgType, const void *msg, size_t msgLength, uint32_t flags) {
	return message_send_event_thread_send_message(self->msg_send, appId, msgType, msg, msgLength, flags);
}
