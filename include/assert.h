#pragma once

#include <assert.h> // IWYU pragma: keep

#if defined (__STDC_VERSION__) && __STDC_VERSION__ <= 201710L
// static_assert is a keyword in c23 and at this time assert.h doesn't propert define the macro
#ifndef static_assert
#define static_assert _Static_assert
#endif
#endif
