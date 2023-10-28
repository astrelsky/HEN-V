#pragma once

#include "pool.h"

#include <stdarg.h>

typedef struct notif_send_event_thread_t notif_send_event_thread_t;

notif_send_event_thread_t *notif_send_event_thread_new(event_thread_pool_t *pool);
void notif_send_event_thread_puts(notif_send_event_thread_t *self, const char *msg);
int notif_send_event_thread_printf(notif_send_event_thread_t *self, const char *msg, ...);
int notif_send_event_thread_vprintf(notif_send_event_thread_t *self, const char *msg, va_list arg);
