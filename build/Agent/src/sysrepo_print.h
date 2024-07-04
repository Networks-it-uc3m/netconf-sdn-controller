#ifndef __SYSREPO_PRINT
#define __SYSREPO_PRINT
#include <string.h>
#include <linux/pfkeyv2.h>
#include <stdlib.h>
#include <sysrepo.h>
#include <sysrepo/values.h>
#include "log.h"
#include "utils.h"
#include <stdio.h>

void print_val(const sr_val_t *value);
void print_current_config(sr_session_ctx_t *session, const char *module_name);
char *ev_to_str(sr_event_t ev);
#endif