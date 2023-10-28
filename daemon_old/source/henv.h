#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct henv_t henv_t;

henv_t *henv_new(void);
void henv_delete(henv_t *self);
void henv_add_launch_listener(henv_t *self, uint32_t sender);
void henv_remove_launch_listener(henv_t *self, uint32_t sender);
void henv_add_prefix_handler(henv_t *self, uint32_t sender, uint32_t prefix);
void henv_remove_prefix_handler(henv_t *self, uint32_t sender, uint32_t prefix);
void henv_notify_launch_listeners(henv_t *restrict self, int pid);
bool henv_notify_prefix_handlers(henv_t *restrict self, int pid);
