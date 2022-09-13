#include "monitor_lock.h"

pthread_mutex_t monitor_sendrecv_mutex = PTHREAD_MUTEX_INITIALIZER;

// protected by monitor_sendrecv_mutex
int monitor_resume_recvd = 0;
pthread_cond_t monitor_resume_recvd_cv = PTHREAD_COND_INITIALIZER; 
