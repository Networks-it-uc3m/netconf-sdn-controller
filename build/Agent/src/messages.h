#ifndef __MESSAGES
#define __MESSAGES

#include "parson.h"
#include "sad_entry.h"




#define NEW_CONFIG_MSG        1 
#define DELETE_CONFIG_MSG     2
#define ALERT_STATE_MSG       3
#define OP_RESULT_MSG         4
// #define REQUEST_entry_MSG     5 For the moment not used.
#define INSERT_ENTRY_MSG      6
#define RETURN_entry_MSG      7 
#define REQUEST_VERIFY_MSG    8
#define ERROR_MSG             -1


#define HASH_MAP_SIZE         33

// default_msg Message format used to share information between the nodes
typedef struct default_msg {
    int work_id;
    int code;
    JSON_Object *data;
} default_msg;

// sad_entry_msg Message used to share the new spa_entry to the trusted part

/// @brief Structure used to share sad_entries between the trusted and the untrusted part
typedef struct sad_entry_msg {
    sad_entry_node *sad_entry;
} sad_entry_msg;


/// @brief Message used to delete a set of entry from the trusted part.
typedef struct delete_config_msg {
  char*  entry_id;
} delete_config_msg;

// alert_state_msg
typedef struct alert_state_msg {
    char* entry_id;
    char message[32];
} alert_state_msg;

// op_result_mgs;


/// @brief It represents the result of the an operation (0 is success / 1 Failt), along a message with the information.
typedef struct op_result_msg {
    int success; // 0 Success / 1 Fail
    char message[HASH_MAP_SIZE];
} op_result_msg;



typedef struct insert_entry_msg 
{
    sad_entry_node *sad_entry;
} insert_entry_msg;



/// @brief function that decodes a json message
/// @param msg decoded message // TODO swich inputs
/// @param schema original schema
/// @return 
int decode_default_msg(JSON_Object *schema, default_msg* msg);


/// @brief function used to encode a json schema into a message
/// @param work_id identifier of the work that is been performed
/// @param code identifier of the type of message
/// @param data data that is been added into the message
/// @return encode message using json format
char *encode_default_msg(int work_id, int code, JSON_Value *data);

// Functions called to decode the messages

/// @brief decode a json object into a sad_entry_msg
/// @param msg return message // TODO switch fields
/// @param schema json schema passed
/// @return 
int decode_sad_entry_msg(JSON_Object *schema, sad_entry_msg *msg);

/// @brief decode a json object into a delete_config_msg
/// @param msg return message // TODO switch fields
/// @param schema json schema passed
/// @return 
int decode_delete_config_msg(JSON_Object *schema, delete_config_msg *msg);

/// @brief decode a json object into a alert_state_msg
/// @param msg return message // TODO switch fields
/// @param schema json schema passed
/// @return 
int decode_alert_state_msg(JSON_Object *schema, alert_state_msg *msg);

/// @brief decode a json object into a op_result_msg
/// @param msg return message // TODO switch fields
/// @param schema json schema passed
/// @return 
int decode_op_result_msg(JSON_Object *schema, op_result_msg *msg);



// Functions to encode the messages

/// @brief encodes a sad_entry_msg into a JSON value
/// @param msg sad_entry_msg to be encoded
/// @return JSON_VALUE to be sent
JSON_Value *encode_sad_entry_msg(sad_entry_msg *msg);

/// @brief encodes a sad_edelete_config_msgntry_msg into a JSON value
/// @param msg delete_config_msg to be encoded
/// @return JSON_VALUE to be sent
JSON_Value *encode_delete_config_msg(delete_config_msg *msg);

/// @brief encodes a alert_state_msg into a JSON value
/// @param msg alert_state_msg to be encoded
/// @return JSON_VALUE to be sent
JSON_Value *encode_alert_state_msg(alert_state_msg *msg);

/// @brief encodes a op_result_msg into a JSON value
/// @param msg op_result_msg to be encoded
/// @return JSON_VALUE to be sent
JSON_Value *encode_op_result_msg(op_result_msg *msg);


/// @brief encodes a insert_entry_msg into a JSON value
/// @param msg insert_entry_msg to be encoded
/// @return JSON_VALUE to be sent
JSON_Value *encode_insert_entry_msg(insert_entry_msg *msg);

// Some helpers to remove redundancy
// TODO remove since it is not used
JSON_Value *generate_op_message(char* message, int code);

#endif