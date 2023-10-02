#pragma once

#include "event.h"
#include "pool.h"

event_thread_t *notif_send_event_thread_new(event_thread_pool_t *pool);
