#include "logging.h"

#include <stdarg.h>
#include <unistd.h>

static char taint_logfile[] = "taint.log";
FILE * taintlog_fp = 0;


int taint_logging_init(void)
{
    taintlog_fp = fopen(taint_logfile, "w");
    if (! taintlog_fp)
    {
        perror("Error opening taint logfile:");
        fprintf(stderr, "Will not log taint events.\n");
        return 1;
    }
    return 0;
}

int taint_logging_stop(void)
{
    if (taintlog_fp)
    {
        int ret = fclose(taintlog_fp);
        if(ret)
        {
            perror("Error closing taint logfile:");
            return 1;
        }
        taintlog_fp = 0;

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
    int ret = vfprintf(taintlog_fp, format, arglist);
    if (ret < 0)
    {
        fprintf(stderr, "WARN: failed to write to the taint logfile.");
    }
    fflush(taintlog_fp);
    fsync(fileno(taintlog_fp));
}