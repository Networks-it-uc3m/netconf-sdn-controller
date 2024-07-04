#ifndef __SYSREPO_ENTRIES
#define __SYSREPO_ENTRIES
#include "utils.h"
#include "spd_entry.h"
#include "sad_entry.h"
#include "pfkeyv2_utils.h"
#include "pfkeyv2_entry.h"
#include <sysrepo.h>
#include <sysrepo/values.h>
#include <libyang/libyang.h>
#include "sad_entry.h"
#include "spd_entry.h"
#include "log.h"
#include <pthread.h>

#ifdef Enarx
#include "trust_client.h"
#include "messages.h"
#endif


// TODO move this to another module so it can be used without importing the sysrepo_entries.h
spd_entry_node *get_spd_node(char *name);
spd_entry_node *get_spd_node_by_index(int policy_index);

void print_current_config(sr_session_ctx_t *session, const char *module_name);


/// @brief Function that handles the event of a new spd entry in the Sysrepo database and stores it the kernel through the PF_KEY management api
/// @param sess 
/// @param it 
/// @param xpath Location of the SPD entry
/// @param spd_name Identifier of the SPD 
/// @param case_value // TODO remove
/// @return 
int addSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *spd_name, int case_value);


/// @brief Function that handles the event when a SPD entry is being removed from the Sysrepo database
/// @param sess  // TODO remove
/// @param it  // TODO remove
/// @param xpath  // TODO remove
/// @param spd_name Identifier of the SPD entry to be removed
/// @param case_value // TODO remove (this is for other cases)
/// @return 
int removeSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *spd_name, int case_value);



/// @brief Function that reads a SPD entry from the sysrepo database
/// @param sess 
/// @param it 
/// @param xpath Location of the entry in the sysrepo database
/// @param spd_node parsed spd_entry_node, obtained from the sysrepo database
/// @param case_value // TODO remove
/// @return 
int readSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,spd_entry_node *spd_node, int case_value);


/// @brief Function that handles the event of a new sad entry in the Sysrepo database and stores it the kernel through the PF_KEY management api
/// @param sess 
/// @param it 
/// @param xpath XML path to locate the stored values of the SAD entry in the sysrepo database
/// @param sad_name Value that identifies a sad entry by their spi and target src/dst addresses
/// @return 
int addSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *sad_name);


/// @brief Function that handles the event when a SAD entry is being removed from the Sysrepo database
/// @param sess // TODO REMOVE unused input
/// @param it // TODO REMOVE unused input
/// @param xpath // TODO REMOVE unused input
/// @param sad_name Value that identifies a sad entry by their spi and target src/dst addresses
/// @return 
int removeSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it, char *xpath,char *sad_name);

/// @brief Function that reads a SAD entry from the sysrepo database
/// @param sess 
/// @param it 
/// @param xpath Location of the entry in the sysrepo database
/// @param sad_node parsed sad_entry_node, obtained from the sysrepo database
/// @return 
int readSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,sad_entry_node *sad_node);



/// @brief Function that generates a netconf notification so it can alert all the subscribed stakeholders through sysrepo
/// @param session 
/// @param spi SPI value associated with the SAD entry to be removed
/// @param soft If the expire is a soft-expire (Entry not removed from kernel) or hard (the entry has been removed)
/// @return 
int send_sa_expire_notification(sr_session_ctx_t *session, unsigned long int spi, bool soft);

/// @brief Function that removes a SAD entry from sysrepo. Only used after receiving a HARD expire
/// @param spi SPI of the entry that has been removed
/// @return 
int send_delete_SAD_request(unsigned long int spi);


#ifdef Enarx
void verify_sad_nodes();
#endif 

#endif