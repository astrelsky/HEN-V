#include "henv.h"
#include "msg.h"
#include "pool.h"
#include "set.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_APPLICATIONS 32 // hardcoded limitation in SceSysCore

#define LOG_ERROR_WITH_CHECK(var, fn, check) \
	int var = fn; \
	if (check) {\
		print_error(__FUNCTION__, var);\
	}\

#define LOG_ERROR(var, fn) LOG_ERROR_WITH_CHECK(var, fn, var != 0)
#define LOG_ERROR_IGNORE_EDEADLK(var, fn) LOG_ERROR_WITH_CHECK(var, fn, var != 0 && var != EDEADLK)

typedef struct henv_t {
	pthread_rwlock_t mtx;
	set_uint_t launch_listeners;
	set_uint_t prefix_handlers; // FIXME: this needs to correlate appids to prefixes
	event_thread_pool_t *pool;
} henv_t;

static void print_error(const char *msg, int err) {
	printf("%s: %s\n", msg, strerror(err)); // NOLINT(concurrency-mt-unsafe)
}

static void henv_init(henv_t *self) {
	LOG_ERROR(err, pthread_rwlock_init(&self->mtx, NULL));
	set_uint_init(&self->launch_listeners, MAX_APPLICATIONS);
	set_uint_init(&self->prefix_handlers, MAX_APPLICATIONS);
}

static void henv_finalize(henv_t *self) {
	LOG_ERROR(err, pthread_rwlock_destroy(&self->mtx));
	set_uint_finalize(&self->launch_listeners);
	set_uint_finalize(&self->prefix_handlers);
}

static int henv_rlock(henv_t *self) {
	// EDEADLK means the current thread already has the lock
	LOG_ERROR_IGNORE_EDEADLK(err, pthread_rwlock_rdlock(&self->mtx));
	return err;
}

static int henv_lock(henv_t *self) {
	LOG_ERROR_IGNORE_EDEADLK(err, pthread_rwlock_wrlock(&self->mtx));
	return err;
}

static int henv_unlock(henv_t *self) {
	LOG_ERROR(err, pthread_rwlock_unlock(&self->mtx));
	return err;
}

henv_t *henv_new(void) {
	henv_t *self = malloc(sizeof(henv_t));
	if (self == NULL) {
		exit(ENOMEM); // NOLINT(concurrency-mt-unsafe)
	}
	henv_init(self);
	return self;
}

void henv_delete(henv_t *self) {
	if (self != NULL) {
		henv_finalize(self);
		free(self);
	}
}

void henv_add_launch_listener(henv_t *self, uint32_t sender) {
	if (henv_lock(self) != 0) {
		printf("failed to launch listener 0x%x\n", sender);
		return;
	}
	defer_stack_push(henv_unlock, self);
	set_uint_add(&self->launch_listeners, sender);
	defer_stack_pop();
	henv_unlock(self);
}

void henv_remove_launch_listener(henv_t *self, uint32_t sender) {
	if (henv_lock(self) != 0) {
		printf("failed to remove listener 0x%x\n", sender);
		return;
	}
	defer_stack_push(henv_unlock, self);
	set_uint_remove(&self->launch_listeners, sender);
	defer_stack_pop();
	henv_unlock(self);
}

void henv_add_prefix_handler(henv_t *self, uint32_t sender, uint32_t prefix) {
	if (henv_lock(self) != 0) {
		char str[4 + 1];
		*(uint32_t *)str = prefix;
		str[4] = '\0';
		printf("failed to add prefix handler 0x%x for %s\n", sender, str);
		return;
	}
	defer_stack_push(henv_unlock, self);
	set_uint_add(&self->prefix_handlers, sender);
	defer_stack_pop();
	henv_unlock(self);
}

void henv_remove_prefix_handler(henv_t *self, uint32_t sender, uint32_t prefix) {
	if (henv_lock(self) != 0) {
		char str[4 + 1];
		*(uint32_t *)str = prefix;
		str[4] = '\0';
		printf("failed to remove prefix handler 0x%x for %s\n", sender, str);
		return;
	}
	defer_stack_push(henv_unlock, self);
	set_uint_remove(&self->prefix_handlers, sender);
	defer_stack_pop();
	henv_unlock(self);
}

void henv_notify_launch_listeners(henv_t *restrict self, int pid) {
	if (henv_rlock(self) != 0) {
		puts("failed to notify launch listeners");
		return;
	}
	defer_stack_push(henv_unlock, self);
	for (const uint32_t *restrict it = self->launch_listeners.first; it != self->launch_listeners.last; ++it) {
		event_thread_pool_send_message(self->pool, *it, BREW_MSG_TYPE_APP_LAUNCHED, &pid, sizeof(pid), 0);
	}
	defer_stack_pop();
	henv_unlock(self);
}

bool henv_notify_prefix_handlers(henv_t *restrict self, int pid) {
	if (henv_rlock(self) != 0) {
		puts("failed to notify prefix handlers");
		return false;
	}
	defer_stack_push(henv_unlock, self);

	bool result = false;

	// FIXME
	(void) pid;

	defer_stack_pop();
	henv_unlock(self);
	return result;
}
