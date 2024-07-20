#include "trust_handler.h"

sad_entry_node *trusted_init_sad_node = NULL;


extern char *handle_message(char *data) {

    default_msg *msg = malloc(sizeof(default_msg));
    int result = 0;
    int code = 0;
    JSON_Value *data_value;;
    JSON_Object *schema = json_object(json_parse_string(data));
    if (schema == NULL) {
        int result = -1;
        int code = -1;
        data_value = generate_op_message("WRONG JSON",-1);    
        goto cleanup;
    }
    // TODO handle error of decode_default
    if (schema == NULL || decode_default_msg(schema, msg) != 0) {
        // TODO handle error of decode_default
        goto cleanup;
    } 

    switch (msg->code) {
        case NEW_CONFIG_MSG: {
            sad_entry_msg *entry_msg = (sad_entry_msg*) malloc(sizeof(sad_entry_msg));    
            if ((result = handle_new_conf_message(msg->data,entry_msg)), result != 0) {
                free(entry_msg);
                data_value = generate_op_message("newconf err",result);
                code = OP_RESULT_MSG;
            } else {
                data_value = encode_sad_entry_msg(entry_msg);
                code = INSERT_ENTRY_MSG;
                // INFO("NEW CONFIG MANAGED SUCCESFUL");
            }
            break;
        }
        case REQUEST_VERIFY_MSG: {
            alert_state_msg *alert_msg = (alert_state_msg*) malloc(sizeof(alert_state_msg));
            alert_msg->entry_id = (char *) malloc(sizeof(char) * MAX_PATH); 
            if (result = handle_request_verify_message(msg->data,alert_msg), result == 0) {
                // The confirmation has been succesfull
                data_value = generate_op_message("SAD_ENTRY is valid",0);
                code = OP_RESULT_MSG;
                // INFO("VERIFY MANAGED SUCCESFUL");
            } else if (result  == 2){
                data_value = encode_alert_state_msg(alert_msg);
                code = ALERT_STATE_MSG;
                // Show the hash, reqid, and spi
                
            } else {
                data_value = generate_op_message("Verify error",result);
                code = OP_RESULT_MSG;
            }
            free(alert_msg);
            break;
        }
        case DELETE_CONFIG_MSG: {
            op_result_msg *op_msg = (op_result_msg*) malloc(sizeof(op_result_msg));    
            if (result = handle_request_remove(msg->data,op_msg), result != 0) {
                ERR("Error deleting entry");
            } else {
                INFO("DELETE MANAGED SUCCESFUL");
            }
            data_value = encode_op_result_msg(op_msg);
            code = OP_RESULT_MSG;
            free(op_msg);
            break;
        }
    }
    char *out_data;
cleanup:
    out_data = encode_default_msg(msg->work_id,code,data_value);
    // free(msg);
    // return out_data;
    // if (data_value != NULL) {
    //     json_value_free(data_value);
    // }
    return out_data;
}

// TODO change order of input parameters
int handle_new_conf_message(JSON_Object *data, sad_entry_msg *out) {
    int status = 0;
    // Decode the data of the message
    sad_entry_msg *config = (sad_entry_msg*) malloc(sizeof(sad_entry_msg)); 
    if (decode_sad_entry_msg(data, config) != 0) {
        ERR("Error decoding the data of the message");
        status = 1;
        goto cleanup;
    }
    sad_entry_node *entry = (sad_entry_node*) malloc(sizeof(sad_entry_node));
    // Copy struct into another so we can free later the config value
    memcpy(&entry, &config->sad_entry, sizeof(config->sad_entry));
    // Just strcpy the auth and encryption key seems to be missing in RUST implementation after been added into the map
    strcpy(entry->encryption_key,config->sad_entry->encryption_key);
    strcpy(entry->integrity_key,config->sad_entry->integrity_key);
    // XOR the key parameters
    // TODO Add this part
    // Store the values
    
    if (get_sad_node(trusted_init_sad_node,entry->name) != NULL) {
        ERR("Error adding sad_entry, it already exists");
        status =  1;
        goto cleanup;
    }

    if (add_sad_node(&trusted_init_sad_node,entry) != 0) {
        ERR("Error adding sad_entry, it already exists");
        status =  1;
        goto cleanup;
    }


    // strcpy(out->entry_id,hash);
    out->sad_entry = entry;
    INFO("Added SAD entry: HASH: %s \t SPI: %d \t REQID: %d",
    entry->name,entry->spi,entry->req_id);
cleanup:
    // Free data
	free(config);
    return status;
}


int handle_request_verify_message(JSON_Object *data, alert_state_msg *out) {
    int status = 0;
    // Decode the data of the message
    sad_entry_msg *config = (sad_entry_msg*) malloc(sizeof(sad_entry_msg));

    if (decode_sad_entry_msg(data, config) != 0) {
        ERR("Error decoding the data of the message");
        status = 1;
        goto cleanup;
    };

    // Check if hash is equal to entry_id Do no check for this since this needs to be calculated by the trusted app
    // if (sizeof(config->entry_id) != sizeof(hash) && strcmp(config->entry_id,hash) != 0) {
    //     ERR("Hash not equal");
    //     status = 1;
    //     goto cleanup;
    // }
    sad_entry_node *received_entry = config->sad_entry;
    sad_entry_node *stored_entry = get_sad_node(&trusted_init_sad_node,received_entry->name);
    if (stored_entry == NULL) {
        ERR("Entry not found");
        status = 1;
        goto cleanup;
    }
    
    // Is the same entry?
    if (compare_sad_entries(config->sad_entry,stored_entry) != 0) {
        // Generate out message
        strcpy(out->message, "entries differ");
        strcpy(out->entry_id,config->sad_entry->name);
        status = 2;
        ERR("Entry could not be validated: Name: %s\tSPI: %d\tREQID: %d",stored_entry->name, stored_entry->spi,stored_entry->req_id);
        ERR("\n\tStored AUTH_KEY: %s \t Current AUTH_KEY: %s \n\tStored ENC_KEY: %s \t Current ENC_KEY: %s",stringToBytes(stored_entry->integrity_key),stringToBytes(received_entry->integrity_key),stringToBytes(stored_entry->encryption_key),stringToBytes(received_entry->encryption_key));
        goto cleanup;
    } else {
        INFO("Entry validated: Name: %s\tSPI: %d\tREQID: %d",stored_entry->name, stored_entry->spi,stored_entry->req_id);
    }
cleanup:
	free(config);
    return status;
}


int handle_request_remove(JSON_Object *data, op_result_msg *out) {
    int status = 0;
    char message[16];
    // Decode the data of the message
    delete_config_msg *config = (delete_config_msg*) malloc(sizeof(delete_config_msg));
    if (decode_delete_config_msg(data, config) != 0) {
        ERR("Error decoding the data of the message");
        strcpy(message,"decoding\0");
        status = 1;
        goto cleanup;
    }

    // Does the sad entry exists?
    sad_entry_node *stored_entry = get_sad_node(&trusted_init_sad_node,config->entry_id);
    if (stored_entry == NULL) {
        ERR("SAD entry with id %s does not exists",config->entry_id);
        strcpy(message,"do not exist\0");
        status = 1;
        goto cleanup;
    }
    
    strcpy(message,"deleted\0");
    // Delete the sad entry
    INFO("Deleted SAD entry: Name: %s \t SPI: %d \t REQID: %d", config->entry_id,stored_entry->spi,stored_entry->req_id);
    del_sad_node(&trusted_init_sad_node,config->entry_id);
cleanup:
	free(config);
    strcpy(out->message, message);
    out->success = status;
    return status;
}



