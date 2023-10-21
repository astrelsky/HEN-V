#include "event.h"
#include "chan.h"

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>

// this is large enough that the channels shouldn't block when being written to
#define DEFAULT_CHANNEL_CAPACITY 16

static thread_local event_thread_t *g_current_event_thread;

typedef struct {
	defer_stack_callback_t fn;
	void *args;
} defer_stack_entry_t;

typedef struct defer_stack_t {
	defer_stack_entry_t *first;
	defer_stack_entry_t *last;
	defer_stack_entry_t *eos;
} defer_stack_t;

static void defer_stack_init(defer_stack_t *restrict self) {
	self->first = malloc(sizeof(defer_stack_entry_t));
	if (self->first == NULL) {
		exit(ENOMEM); // NOLINT(concurrency-mt-unsafe)
	}
	self->last = self->first;
	self->eos = self->last + 1;
}

defer_stack_t *defer_stack_new(void) {
	defer_stack_t *self = malloc(sizeof(defer_stack_t));
	if (self == NULL) {
		exit(ENOMEM); // NOLINT(concurrency-mt-unsafe)
	}
	defer_stack_init(self);
	return self;
}

static size_t defer_stack_length(const defer_stack_t *restrict self) {
	return self->last - self->first;
}

static void defer_stack_grow(defer_stack_t *restrict self, size_t n) {
	const size_t length = defer_stack_length(self);
	defer_stack_entry_t *ptr = realloc(self->first, length + n);
	if (ptr == NULL) {
		exit(ENOMEM); // NOLINT(concurrency-mt-unsafe)
	}
	self->first = ptr;
	self->last = ptr + length;
	self->eos = ptr + length + n;
}

static void defer_stack_finalize(defer_stack_t *restrict self) {
	free(self->first);
}

void defer_stack_delete(defer_stack_t *restrict self) {
	if (self != NULL) {
		defer_stack_finalize(self);
		free(self);
	}
}

static void defer_stack_push_internal(defer_stack_t *restrict self, defer_stack_callback_t fn, void *args) {
	if (self->last == self->eos) {
		defer_stack_grow(self, 1);
	}
	*self->last++ = (defer_stack_entry_t) {
		.fn = fn,
		.args = args
	};
}

static void defer_stack_pop_internal(defer_stack_t *restrict self) {
	self->last -= 1;
}

static void defer_stack_clear(defer_stack_t *restrict self) {
	self->last = self->first;
}

static void defer_stack_run(defer_stack_t *restrict self) {
	if (self == NULL) {
		return;
	}

	for (defer_stack_entry_t *restrict it = self->last; it != self->first; --it) {
		it->fn(it->args);
	}
	defer_stack_clear(self);
}

static const struct event_thread_vtable g_event_thread_vtable;

/*
// TODO create some kind of manager to hold this instead of a global
static event_thread_t *g_event_threads[] = {
	NULL
};
*/

void event_thread_init(event_thread_t *self, const char *name, struct event_thread_pool *pool, sigjmp_buf *jmpbuf, thread_function_t fun) {
	g_current_event_thread = self;
	*self = (event_thread_t) {
		._vptr = &g_event_thread_vtable,
		.name = name,
		.pool = pool,
		.channel = chan_init(DEFAULT_CHANNEL_CAPACITY),
		.jmpbuf = jmpbuf,
		.fun = fun,
		.thread = {
			.td = NULL,
			.retval = NULL,
			.joined = false
		},
		.defer_stack = defer_stack_new()
	};
}

void event_thread_restart(event_thread_t *self) {
	if (self->jmpbuf != NULL) {
		siglongjmp(*self->jmpbuf, 1);
	}
	event_thread_kill(self);
}

void __attribute__((noreturn)) event_thread_kill(event_thread_t *self) {
	self->_vptr->finalize(self);
	pthread_exit(NULL);
}

void event_thread_finalize(event_thread_t *self) {
	chan_close(self->channel);
	if (pthread_self() != self->thread.td) {
		// ensure we don't join ourselves
		thread_join(&self->thread, NULL);
	}
	chan_dispose(self->channel);
	defer_stack_delete(self->defer_stack);
}

void *event_thread_run(event_thread_t *self) {
	while (true) {
		if (sigsetjmp(*self->jmpbuf, true) == 0) {
			return self->fun(self);
		}
		printf("resetting event thread %s\n", self->name);
		self->_vptr->reset(self);
	}
}

void event_thread_start(event_thread_t *self) {
	pthread_create(&self->thread.td, NULL, self->fun, self);
}

void event_thread_join(event_thread_t *self) {
	thread_join(&self->thread, NULL);
}

void event_thread_reset(event_thread_t *self) {
	// do nothing by default
	(void)self;
}

void event_thread_defer_push(event_thread_t *self, defer_stack_callback_t fn, void *args) {
	defer_stack_push_internal(self->defer_stack, fn, args);
}

void event_thread_defer_pop(event_thread_t *self) {
	defer_stack_pop_internal(self->defer_stack);
}

/*
event_thread_t *get_current_event_thread(void) {
	pthread_t self = pthread_self();
	for (event_thread_t **it = g_event_threads; *it != NULL; it++) {
		event_thread_t *event = *it;
		if (event->thread.td == self) {
			return event;
		}
	}
	return NULL;
}
*/

static void event_thread_signal_handler(int sig) {
	if (sig == SIGSEGV || sig == SIGILL) {
		event_thread_t *td = event_thread_get_current_event_thread();
		if (td != NULL) {
			defer_stack_run(td->defer_stack);
			td->_vptr->reset(td);
		}
	}
}

event_thread_t *event_thread_get_current_event_thread(void) {
	return g_current_event_thread;
}

void event_thread_signal_handler_init(void) {
	signal(SIGSEGV, event_thread_signal_handler);
	signal(SIGILL, event_thread_signal_handler);
}

static const struct event_thread_vtable g_event_thread_vtable = {
	.finalize = event_thread_finalize,
	.reset = event_thread_reset,
};
