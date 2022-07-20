#include "logging.h"

#include <stdio.h>
#include <stdarg.h>

static char taint_logfile[] = "taint.log";
static FILE * taint_fp = 0;


int taint_logging_init(void)
{
    taint_fp = fopen(taint_logfile, "w");
    if (! taint_fp)
    {
        perror("Error opening taint logfile:");
        fprintf(stderr, "Will not log taint events.\n");
        return 1;
    }
    return 0;
}

int taint_logging_stop(void)
{
    if (taint_fp)
    {
        int ret = fclose(taint_fp);
        if(ret)
        {
            perror("Error closing taint logfile:");
            return 1;
        }
        taint_fp = 0;
    }
    return 0;
}

int taint_log(char const * format, ...)
{
    va_list arglist = {0};
    va_start(arglist, format);
    vfprintf(taint_fp, format, arglist);
}