#pragma once

#if (__STDC_VERSION__ < 202311L)
#ifndef thread_local
#define thread_local _Thread_local
#endif
#endif
