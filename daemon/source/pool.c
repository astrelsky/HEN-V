#include "ipc.h"
#include "msg.h"
#include "notification.h"
#include "pool.h"

#include <stdlib.h>
#include <stdio.h>

typedef struct event_thread_pool {
	event_thread_t *ipc;
	event_thread_t *elfldr;
	event_thread_t *msg_send;
	event_thread_t *msg_recv;
	event_thread_t *notif;
} event_thread_pool_t;

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
		.msg_recv =message_recv_event_thread_new(self),
		.notif = notif_send_event_thread_new(self)
	};

	return self;
}

static void *delete_event_thread(event_thread_t *self) {
	if (self != NULL) {
		self->_vptr->finalize(self);
	}
	return NULL;
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
	free(self);
}

event_thread_t *event_thread_pool_get_ipc_thread(event_thread_pool_t *self) {
	return self->ipc;
}

event_thread_t *event_thread_pool_get_elfldr_thread(event_thread_pool_t *self) {
	return self->elfldr;
}

event_thread_t *event_thread_pool_get_msg_send_thread(event_thread_pool_t *self) {
	return self->msg_send;
}
