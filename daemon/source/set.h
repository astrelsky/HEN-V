#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// NOLINTBEGIN(concurrency-mt-unsafe)

#define VECTOR_UINT_DEFAULT_CAPACITY (16/sizeof(unsigned int))

typedef struct {
	unsigned int *first;
	unsigned int *last;
	unsigned int *eos;
} set_uint_t;

static inline void set_uint_init(set_uint_t *restrict self) {
	self->first = malloc(VECTOR_UINT_DEFAULT_CAPACITY * sizeof(unsigned int));
	self->last = self->first;
	self->eos = self->first;
}

static inline void set_uint_finalize(set_uint_t *restrict self) {
	free(self->first);
	self->first = NULL;
}

static inline set_uint_t *set_uint_new(void) {
	set_uint_t *self = malloc(sizeof(set_uint_t));
	set_uint_init(self);
	return self;
}

static inline void set_uint_delete(set_uint_t *restrict self) {
	if (self != NULL) {
		set_uint_finalize(self);
		free(self);
	}
}

static inline void set_uint_clear(set_uint_t *restrict self) {
	self->first = self->last;
}

static inline size_t set_uint_length(const set_uint_t *restrict self) {
	return self->last - self->first;
}

static inline long set_uint_find(const set_uint_t *restrict self, unsigned int value) {
	const size_t length = set_uint_length(self);
	long lo = 0;
	long hi = ((long)length) - 1;

	while (lo <= hi) {
		const long m = (lo + hi) >> 1;
		const long n = self->first[m] - value;

		if (n == 0) {
			return m;
		}

		if (n < 0) {
			lo = m + 1;
		} else {
			hi = m - 1;
		}
	}
	return -(lo + 1);
}

static inline void set_uint_grow(set_uint_t *restrict self, size_t n) {
	const size_t length = set_uint_length(self);
	unsigned int *ptr = realloc(self->first, (length + n) * sizeof(unsigned int));
	if (ptr == NULL) {
		exit(ENOMEM);
	}
	self->first = ptr;
	self->last = ptr + length;
	self->eos = self->last + n;
}

static inline void set_uint_add(set_uint_t *restrict self, unsigned int value) {
	long i = set_uint_find(self, value);
	if (i >= 0) {
		return;
	}

	if (self->last == self->eos) {
		set_uint_grow(self, VECTOR_UINT_DEFAULT_CAPACITY);
	}

	i = -(i + 1);

	memcpy(self->first + i + 1, self->first + i, self->last++ - (self->first + i));

	self->first[i] = value;
}

static inline unsigned int set_uint_remove(set_uint_t *restrict self, size_t i) {
	unsigned int value = self->first[i];
	memcpy(self->first + i, self->first + i + 1, self->last - (self->first + i + 1));
	--self->last;
	return value;
}

static inline bool set_uint_contains(const set_uint_t *restrict self, unsigned int value) {
	return set_uint_find(self, value) >= 0;
}

// NOLINTEND(concurrency-mt-unsafe)
