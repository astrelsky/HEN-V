#pragma once

#include <stdint.h>
#include <stdlib.h>

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
	BREW_MSG_TYPE_APP_LAUNCHED
} homebrew_daemon_message_type_t;
