#include "messages.h"
#include "log.h"



int decode_default_msg(JSON_Object *schema, default_msg* msg) {
    msg->work_id = json_object_get_number(schema,"work_id");
    msg->code = json_object_get_number(schema,"code");
    msg->data = json_object_get_object(schema,"data");
    return 0;
}

char *encode_default_msg(int work_id, int code, JSON_Value *data) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object, "work_id", work_id);
    json_object_set_number(root_object, "code", code);
    json_object_set_value(root_object, "data", data);
    return json_serialize_to_string_pretty(root_value);
}


int decode_sad_entry_msg(JSON_Object *schema, sad_entry_msg *msg) {
    msg->sad_entry = deserialize_sad_node(json_object_get_object(schema,"sad_entry"));
    return 0;
}

JSON_Value *encode_sad_entry_msg(sad_entry_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_value(root_object, "sad_entry", serialize_sad_node(msg->sad_entry));
    return root_value;
}

int decode_delete_config_msg(JSON_Object *schema, delete_config_msg *msg) {
    strcpy(msg->entry_id,json_object_get_string(schema,"entry_id"));
    return 0;
}

JSON_Value *encode_delete_config_msg(delete_config_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object,"entry_id",msg->entry_id);
    return root_value;
}

int decode_alert_state_msg(JSON_Object *schema, alert_state_msg *msg) {
    strcpy(msg->entry_id,json_object_get_string(schema,"entry_id"));
    strcpy(msg->message,json_object_get_string(schema,"message"));
    return 0;
}

JSON_Value *encode_alert_state_msg(alert_state_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object,"entry_id",msg->entry_id);
    json_object_set_string(root_object,"message",msg->message);
    return root_value;
}


int decode_op_result_msg(JSON_Object *schema, op_result_msg *msg) {
    msg->success = json_object_get_number(schema,"success");
    strcpy(msg->message,json_object_get_string(schema,"message"));
    return 0;
}

JSON_Value *encode_op_result_msg(op_result_msg *msg) {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object,"success",msg->success);
    json_object_set_string(root_object,"message",msg->message);
    return root_value;
}


JSON_Value *generate_op_message(char* message, int code) {
    op_result_msg *out = (op_result_msg*) malloc(sizeof(op_result_msg));
    strcpy(out->message,message);
    out->success = code;
    JSON_Value *out_value = encode_op_result_msg(out);
    free(out);
    return out_value;
}

