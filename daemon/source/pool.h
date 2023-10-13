#pragma once

#include "event.h"


typedef struct event_thread_pool event_thread_pool_t;

event_thread_pool_t *event_thread_pool_new(void);
void event_thread_pool_delete(event_thread_pool_t *self);
event_thread_t *event_thread_get_current_event_thread(event_thread_pool_t *self);
event_thread_t *event_thread_pool_get_ipc_thread(event_thread_pool_t *self);
event_thread_t *event_thread_pool_get_elfldr_thread(event_thread_pool_t *self);
event_thread_t *event_thread_pool_get_msg_send_thread(event_thread_pool_t *self);
void event_thread_pool_join(event_thread_pool_t *self);
void event_thread_pool_wait(event_thread_pool_t *self);
void event_thread_pool_kill(event_thread_pool_t *self);
void event_thread_pool_start(event_thread_pool_t *self);
int event_thread_pool_send_notification(event_thread_pool_t *self, const char *msg, ...);
