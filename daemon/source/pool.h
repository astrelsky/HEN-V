#pragma once

#include "event.h"


typedef struct event_thread_pool event_thread_pool_t;

event_thread_pool_t *event_thread_pool_new(void);
void event_thread_pool_delete(event_thread_pool_t *self);
event_thread_t *event_thread_get_current_event_thread(event_thread_pool_t *self);
event_thread_t *event_thread_pool_get_ipc_thread(event_thread_pool_t *self);
event_thread_t *event_thread_pool_get_elfldr_thread(event_thread_pool_t *self);
event_thread_t *event_thread_pool_get_msg_send_thread(event_thread_pool_t *self);
