#pragma once

#include "chan.h"
#include "thread.h"

#include <setjmp.h> // IWYU pragma: keep
#include <stdint.h>

// NOTE: each event thread should perform ONE task
typedef struct event_thread event_thread_t;

struct event_thread_vtable {
	void (*finalize)(event_thread_t *self);
	void (*reset)(event_thread_t *self);
};

typedef void *(*thread_function_t)(void *);

typedef struct event_thread {
	const struct event_thread_vtable *_vptr;
	const char *name;
	struct event_thread_pool *pool;
	chan_t *channel;
	sigjmp_buf *jmpbuf;
	thread_function_t fun;
	thread_t thread;
} event_thread_t;

void event_thread_init(event_thread_t *self, const char *name, struct event_thread_pool *pool, sigjmp_buf *jmpbuf, thread_function_t fun);
void __attribute__((noreturn)) event_thread_kill(event_thread_t *self);
void event_thread_start(event_thread_t *self);
void event_thread_finalize(event_thread_t *self);
void event_thread_reset(event_thread_t *self);
void event_thread_restart(event_thread_t *self);

void event_thread_close(event_thread_t *self);
void event_thread_join(event_thread_t *self);

void event_thread_signal_handler_init(void);

static inline int event_thread_send(event_thread_t *self, void *data) {
	return chan_send(self->channel, data);
}

static inline int event_thread_recv(event_thread_t *self, void **data) {
	return chan_recv(self->channel, data);
}

static inline int event_thread_send_u32(event_thread_t *self, uint32_t data) {
	return chan_send_int32(self->channel, (int32_t) data);
}

static inline int event_thread_recv_u32(event_thread_t *self, uint32_t *data) {
	return chan_recv_int32(self->channel, (int32_t *) data);
}
