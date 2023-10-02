#pragma once

#include "event.h"
#include "pool.h"

event_thread_t *ipc_event_thread_new(event_thread_pool_t *pool);
event_thread_t *elfldr_event_thread_new(event_thread_pool_t *pool);
