#include "messages.h"
#include <stdio.h>
#include "log.h"
#include "utils.h"
#include "sad_entry.h"
#ifndef __TRUST_HANDLER
#define __TRUST_HANDLER


/// @brief function that handles a message containing a new configuration (SAD entry)
/// @param data input message
/// @param out output message
/// @return 
int handle_new_conf_message (JSON_Object *data, sad_entry_msg *out);

/// @brief function that handles the verification request
/// @param data 
/// @param out 
/// @return 
int handle_request_verify_message(JSON_Object *data, alert_state_msg *out);

/// @brief function that handles a message requesting to remove a configuration (SAD entry)
/// @param data 
/// @param out 
/// @return 
int handle_request_remove(JSON_Object *data, op_result_msg *out);

/// @brief function that handles an incomming message and takes the necessary actions
/// @param data 
/// @return 
extern char *handle_message(char *data);


#endif