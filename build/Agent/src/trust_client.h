#ifndef __TRUST_CLIENT
#define __TRUST_CLIENT

#include "sad_entry.h"
#include "spd_entry.h"
#include "log.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


/// @brief function to connect to the TA
/// @return 
int connect_ta();

/// @brief function that disconnects from the TA
/// @return 
int disconnect_ta();

/// @brief function that adds a new SAD entry to the TA
/// @param new_sad 
/// @param old_sad // We may need to switch inputs
/// @return 
int add_trusted_sad_entry(sad_entry_node *new_sad, sad_entry_node *old_sad);

/// @brief function that deletes a sad entry 
/// @param sad_node 
/// @return 
int del_trusted_sad_entry(char *sad_name);


/// @brief function that verifies a SAD entry
/// @param alert_msg 
/// @param sad_node 
/// @return 
int verify_trusted_sad_entry(char *alert_msg, sad_entry_node *sad_node);

#endif