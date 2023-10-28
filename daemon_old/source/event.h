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

typedef void (*defer_stack_callback_t)(void *);
typedef struct defer_stack_t defer_stack_t;

defer_stack_t *defer_stack_new(void);
void defer_stack_delete(defer_stack_t *restrict self);

typedef struct event_thread {
	const struct event_thread_vtable *_vptr;
	const char *name;
	struct event_thread_pool *pool;
	chan_t *channel;
	sigjmp_buf *jmpbuf;
	thread_function_t fun;
	thread_t thread;
	defer_stack_t *defer_stack;
} event_thread_t;

void event_thread_init(event_thread_t *self, const char *name, struct event_thread_pool *pool, sigjmp_buf *jmpbuf, thread_function_t fun);
void __attribute__((noreturn)) event_thread_kill(event_thread_t *self);
void event_thread_start(event_thread_t *self);
void event_thread_finalize(event_thread_t *self);
void event_thread_reset(event_thread_t *self);
void event_thread_restart(event_thread_t *self);

void event_thread_join(event_thread_t *self);

void event_thread_signal_handler_init(void);
void event_thread_defer_push(event_thread_t *self, defer_stack_callback_t fn, void *args);
void event_thread_defer_pop(event_thread_t *self);

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

static inline void event_thread_close(event_thread_t *self) {
	chan_close(self->channel);
}

event_thread_t *event_thread_get_current_event_thread(void);

// for use when you don't have the current event thread
static inline void defer_stack_push(defer_stack_callback_t fn, void *args) {
	event_thread_t *td = event_thread_get_current_event_thread();
	event_thread_defer_push(td, fn, args);
}

// for use when you don't have the current event thread
static inline void defer_stack_pop(void) {
	event_thread_defer_pop(event_thread_get_current_event_thread());
}
