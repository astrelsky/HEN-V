#pragma once

// hack fix for misuse of pure attribute in PS5SDK headers

#include_next <sys/cdefs.h>
#ifdef __pure
#undef __pure
#define __pure
#endif
