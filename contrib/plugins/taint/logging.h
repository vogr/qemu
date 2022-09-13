#pragma once

#include <stdio.h>

#ifndef NDEBUG
    #define _DEBUG(...) \
            taint_log(__VA_ARGS__);
    #define _DEBUG_WHERE() \
            taint_log("%s:%d:%s():\n",__FILE__, __LINE__, __func__)
#else
    #define _DEBUG(...) do {} while(0)
    #define _DEBUG_WHERE(...) do {} while(0)
#endif

FILE * taintlog_fp;

int taint_logging_init(void);
int taint_logging_stop(void);
void taint_log(char const * format, ...);