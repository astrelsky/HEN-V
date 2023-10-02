#include "chan.h"
#include "notification.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>

static sigjmp_buf notif_sender_buf;
static const struct event_thread_vtable g_notif_send_event_thread_vtable;

typedef struct {
	event_thread_t base;
	_Atomic(char *) msg;
} notif_send_event_thread_t;

static void *notification_send_thread(notif_send_event_thread_t *self) {
	// TODO
	char *msg = NULL;
	while (chan_recv(self->base.channel, NULL) == 0) {
		atomic_store(&self->msg, msg);
		// TODO: send push notification
		free(atomic_exchange(&self->msg, NULL));
	}

	return NULL;
}

event_thread_t *notif_send_event_thread_new(event_thread_pool_t *pool) {
	notif_send_event_thread_t *self = malloc(sizeof(notif_send_event_thread_t));
	if (self == NULL) {
		perror("notif_send_event_thread_new");
		return NULL;
	}
	event_thread_init(&self->base, "NotificationSendThread", pool, &notif_sender_buf, notification_send_thread);
	self->base._vptr = &g_notif_send_event_thread_vtable;
	atomic_init(&self->msg, NULL);
	return &self->base;
}

static void notif_send_event_thread_reset(notif_send_event_thread_t *self) {
	free(atomic_exchange(&self->msg, NULL));
}

static void notif_send_event_thread_finalize(notif_send_event_thread_t *self) {
	event_thread_finalize(&self->base);
	free(atomic_exchange(&self->msg, NULL));
}

static const struct event_thread_vtable g_notif_send_event_thread_vtable = {
	.finalize = notif_send_event_thread_finalize,
	.reset = notif_send_event_thread_reset,
};
