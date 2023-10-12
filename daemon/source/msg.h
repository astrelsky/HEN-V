#pragma once

#include "event.h"
#include "pool.h"

#include <stdint.h>

typedef struct app_message app_message_t;

extern uint32_t sceAppMessagingSendMsg(uint32_t appId, uint32_t msgType, const void *msg, size_t msgLength, uint32_t flags);

extern int sceAppMessagingReceiveMsg(app_message_t *msg);

#define PAYLOAD_SIZE 8192

typedef struct app_message {
	uint32_t sender;
	uint32_t msgType;
	uint8_t payload[PAYLOAD_SIZE];
	uint32_t payloadSize;
	uint64_t timestamp;
} app_message_t;

typedef enum homebrew_daemon_message_type {
	BREW_MSG_TYPE_REGISTER_PREFIX_HANDLER = 0x1000000,
	BREW_MSG_TYPE_REGISTER_LAUNCH_LISTENER,
	BREW_MSG_TYPE_APP_LAUNCHED,
	BREW_MSG_TYPE_KILL
} homebrew_daemon_message_type_t;

event_thread_t *message_send_event_thread_new(event_thread_pool_t *pool);
event_thread_t *message_recv_event_thread_new(event_thread_pool_t *pool);
