#pragma once

#include <pthread.h>
#include <stdbool.h>

// helper construct to prevent the undefined behavior from joining a pthread multiple times
typedef struct {
	pthread_t td;
	void *retval;
	bool joined;
} thread_t;

static inline int thread_join(thread_t *self, void **retval) {
	int err = 0;
	if (!self->joined) {
		// NOTE: pthread may be safely joined from multiple threads
		// therefore no synchronization is necessary here
		err = pthread_join(self->td, &self->retval);
		self->joined = true;
	}
	if (retval != NULL) {
		*retval = self->retval;
	}
	return err;
}
