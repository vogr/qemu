#pragma once

#include <pthread.h>

extern pthread_mutex_t monitor_sendrecv_mutex;

extern int monitor_resume_recvd;
extern pthread_cond_t monitor_resume_recvd_cv;