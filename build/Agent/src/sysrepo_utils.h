/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __SYSREPO_UTILS
#define __SYSREPO_UTILS
#include <string.h>
#include <sys/socket.h>
#include <linux/pfkeyv2.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sysrepo.h>
#include <sysrepo/values.h>
#include "sysrepo_entries.h"
#include "sysrepo_print.h"
#include "pfkeyv2_entry.h"
#include "pfkeyv2_utils.h"
#include "log.h"
#include "utils.h"



#define XPATH_MAX_LEN 200


/// @brief spd_entry_change_cb  Function that is in charge off handling the changes of the sysrepo database related with the spd xpath (https://netopeer.liberouter.org/doc/sysrepo/master/html/group__change__subs__api.html#gae5634bf3204fc6ac2f7b7564546e3129)
/// @param session required by the sysrepo_module_change_cb callback function
/// @param sub_id required by the sysrepo_module_change_cb callback function
/// @param module_name required by the sysrepo_module_change_cb callback function
/// @param xpath required by the sysrepo_module_change_cb callback function
/// @param event required by the sysrepo_module_change_cb callback function
/// @param request_id required by the sysrepo_module_change_cb callback function
/// @param private_data required by the sysrepo_module_change_cb callback function
/// @return 
int spd_entry_change_cb(sr_session_ctx_t *session,  uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);


/* sad_entry_change_cb
    
    
    
*/

/// @brief Function that is in charge off handling the changes of the sysrepo database related with the SAD entries filtering by their specific XPATH (https://netopeer.liberouter.org/doc/sysrepo/master/html/group__change__subs__api.html#gae5634bf3204fc6ac2f7b7564546e3129)
/// @param session required by the sysrepo_module_change_cb callback function
/// @param sub_id required by the sysrepo_module_change_cb callback function
/// @param module_name required by the sysrepo_module_change_cb callback function
/// @param xpath required by the sysrepo_module_change_cb callback function
/// @param event required by the sysrepo_module_change_cb callback function
/// @param request_id required by the sysrepo_module_change_cb callback function
/// @param private_data required by the sysrepo_module_change_cb callback function
/// @return 
int sad_entry_change_cb(sr_session_ctx_t *session,  uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

/* sadb_register
    Function used to setup a sysrepo session that late will be accessible by other modules
*/

/// @brief Register a socket to the PF_KEY Management API, giving direct access to the sysrepo session
/// @param session 
/// @return 
int sadb_register(sr_session_ctx_t *session);

// TODO make this imports only when using the trusted part of the application

/// @brief When using a trusted application, this process may run in the background so it can verify 
/// @return 
int sad_verification_process();

/// @brief When using a trusted application, this process may run in the background so it can verify 
/// @return 
int close_verification_process();

#endif


