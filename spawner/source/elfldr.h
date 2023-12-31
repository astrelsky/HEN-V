#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct elf_loader elf_loader_t;

// may return NULL
elf_loader_t *elf_loader_create(uint8_t *buf, int pid);
void elf_loader_finalize(elf_loader_t *self);
void elf_loader_delete(elf_loader_t *self);
bool elf_loader_run(elf_loader_t *self);
bool run_elf(uint8_t *buf, int pid);
