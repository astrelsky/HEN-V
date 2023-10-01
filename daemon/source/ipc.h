#pragma once

#include "event.h"

typedef struct {
	const char *path;
	int fd;
	int conn;
} ipc_socket_t;

typedef struct {
	event_thread_t base;
	ipc_socket_t socket;
} ipc_event_thread_t;

void ipc_event_thread_init(ipc_event_thread_t *self);
