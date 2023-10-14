#include "chan.h"
#include "notification.h"

#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NOTIFICATION_MESSAGE_LENGTH 1024

static sigjmp_buf notif_sender_buf;
static const struct event_thread_vtable g_notif_send_event_thread_vtable;

// NOLINTBEGIN

//
typedef struct {
	int type;                //0x00
	int req_id;              //0x04
	int priority;            //0x08
	int msg_id;              //0x0C
	int target_id;           //0x10
	int user_id;             //0x14
	int unk1;                //0x18
	int unk2;                //0x1C
	int app_id;              //0x20
	int error_num;           //0x24
	int unk3;                //0x28
	char use_icon_image_uri; //0x2C
	char message[1024];      //0x2D
	char uri[1024];          //0x42D
	char unkstr[1024];       //0x82D
} SceNotificationRequest;  //Size = 0xC30

extern int sceKernelSendNotificationRequest(int device, SceNotificationRequest *req, size_t size, int blocking);

// NOLINTEND

typedef struct notif_send_event_thread_t {
	event_thread_t base;
	_Atomic(char *) msg;
} notif_send_event_thread_t;

static void *notification_send_thread(notif_send_event_thread_t *self) {
	// NOTE: the receiver of a pointer from a channel takes ownership
	char *msg = NULL;
	static SceNotificationRequest req;
	while (chan_recv(self->base.channel, NULL) == 0) {
		atomic_store(&self->msg, msg);

		strncpy(req.message, msg, sizeof(req.message));

		sceKernelSendNotificationRequest(0, &req, sizeof(req), true);

		free(atomic_exchange(&self->msg, NULL));
	}

	return NULL;
}

notif_send_event_thread_t *notif_send_event_thread_new(event_thread_pool_t *pool) {
	notif_send_event_thread_t *self = malloc(sizeof(notif_send_event_thread_t));
	if (self == NULL) {
		perror("notif_send_event_thread_new");
		return NULL;
	}
	event_thread_init(&self->base, "NotificationSendThread", pool, &notif_sender_buf, notification_send_thread);
	self->base._vptr = &g_notif_send_event_thread_vtable;
	atomic_init(&self->msg, NULL);
	return self;
}

static void notif_send_event_thread_reset(notif_send_event_thread_t *self) {
	free(atomic_exchange(&self->msg, NULL));
}

static void notif_send_event_thread_finalize(notif_send_event_thread_t *self) {
	event_thread_finalize(&self->base);
	free(atomic_exchange(&self->msg, NULL));
}

void notif_send_event_thread_puts(notif_send_event_thread_t *self, const char *msg) {
	// we don't actually need to worry about a trailing newline here
	chan_send(self->base.channel, strdup(msg));
}

int notif_send_event_thread_printf(notif_send_event_thread_t *self, const char *msg, ...) {
	va_list arg;
	va_start(arg, msg);
	int err = notif_send_event_thread_vprintf(self, msg, arg);
	va_end(arg);
	return err;
}

int notif_send_event_thread_vprintf(notif_send_event_thread_t *self, const char *msg, va_list arg) {
	va_list cpy;
	va_copy(cpy, arg);
	int length = vsnprintf(NULL, 0, msg, arg);

	if (length < 0) {
		return length;
	}

	if (length >= NOTIFICATION_MESSAGE_LENGTH) {
		errno = E2BIG;
		return -NOTIFICATION_MESSAGE_LENGTH;
	}

	char *buf = malloc(length + 1);
	if (buf == NULL) {
		errno = ENOMEM;
		return -1;
	}

	int n = vsnprintf(buf, length + 1, msg, arg);

	if (n == length) {
		// ownership is passed to receiver
		chan_send(self->base.channel, buf);
	} else {
		free(buf);
	}

	return n;
}

static const struct event_thread_vtable g_notif_send_event_thread_vtable = {
	.finalize = notif_send_event_thread_finalize,
	.reset = notif_send_event_thread_reset,
};
