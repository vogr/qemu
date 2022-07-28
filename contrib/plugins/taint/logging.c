#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

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

        if(unlink(taint_logfile) < 0)
        {
            perror("Failed to remove taint monitor socket");
            return 1;
        }
    }
    return 0;
}

void taint_log(char const * format, ...)
{
    va_list arglist = {0};
    va_start(arglist, format);
    int ret = vfprintf(taint_fp, format, arglist);
    if (ret < 0)
    {
        fprintf(stderr, "WARN: failed to write to the taint logfile.");
    }
    fflush(taint_fp);
    fsync(fileno(taint_fp));
}