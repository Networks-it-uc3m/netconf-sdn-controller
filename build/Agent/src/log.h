/**
 * Copyright (c) 2020 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#define LOG_VERSION "0.1.0"




typedef struct {
  va_list ap;
  const char *fmt;
  const char *file;
  struct tm *time;
  void *udata;
  int line;
  int level;
} log_Event;

typedef void (*log_LogFn)(log_Event *ev);
typedef void (*log_LockFn)(bool lock, void *udata);

enum {  LOG_FATAL,LOG_ERROR,LOG_WARN,LOG_INFO,  LOG_DEBUG, LOG_TRACE };

#define CI_VERB_FATAL LOG_FATAL
#define CI_VERB_ERROR LOG_ERROR 
#define CI_VERB_WARN LOG_WARN
#define CI_VERB_INFO LOG_INFO
#define CI_VERB_DEBUG LOG_DEBUG
#define CI_VERB_TRACE LOG_TRACE

#define log_trace(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_log(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_log(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#define TRACE(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define DEBUG(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define DBG(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define INFO(...)  log_log(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define WARN(...)  log_log(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define ERROR(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define ERR(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define FATAL(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)  


extern const char* log_level_string(int level);
extern void log_set_lock(log_LockFn fn, void *udata);
extern void log_set_level(int level);
extern void log_set_quiet(bool enable);
extern int log_add_callback(log_LogFn fn, void *udata, int level);
extern int log_add_fp(FILE *fp, int level);
extern int get_verbose_level();
extern void log_log(int level, const char *file, int line, const char *fmt, ...);






#endif