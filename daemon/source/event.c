#include "event.h"
#include "chan.h"

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>

// this is large enough that the channels shouldn't block when being written to
#define DEFAULT_CHANNEL_CAPACITY 16

static const struct event_thread_vtable g_event_thread_vtable;

// TODO create some kind of manager to hold this instead of a global
static event_thread_t *g_event_threads[] = {
	NULL
};

void event_thread_init(event_thread_t *self, const char *name, struct event_thread_pool *pool, sigjmp_buf *jmpbuf, thread_function_t fun) {
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

void event_thread_reset(event_thread_t *self) {
	// do nothing by default
	(void)self;
}

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

static void event_thread_signal_handler(int sig) {
	if (sig == SIGSEGV || sig == SIGILL) {
		event_thread_t *td = get_current_event_thread();
		if (td != NULL) {
			td->_vptr->reset(td);

		}
	}
}

void event_thread_signal_handler_init(void) {
	signal(SIGSEGV, event_thread_signal_handler);
	signal(SIGILL, event_thread_signal_handler);
}

static const struct event_thread_vtable g_event_thread_vtable = {
	.finalize = event_thread_finalize,
	.reset = event_thread_reset,
};
