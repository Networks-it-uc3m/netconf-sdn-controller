#include "sysrepo_print.h"
void print_val(const sr_val_t *value)
{
    if (NULL == value) {
        return;
    }
    DBG("%s ", value->xpath);
    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        DBG("(container)");
        break;
    case SR_LIST_T:
        DBG("(list instance)");
        break;
    case SR_STRING_T:
        DBG("= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        DBG("= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        DBG("= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        DBG("= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        DBG("= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        DBG("= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        DBG("= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        DBG("= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        DBG("= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        DBG("= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        DBG("= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        DBG("= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        DBG("= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        DBG("= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        DBG("= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        DBG("= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        DBG("(empty leaf)");
        break;
    default:
        DBG("(unprintable)");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        // DBG("\n");
        break;
    default:
        // DBG("%s\n", value->dflt ? " [default]" : "");
        break;
    }
}

void print_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *xpath;
    asprintf(&xpath, "/%s:*//.", module_name);
    rc = sr_get_items(session, xpath, 0, 0, &values, &count);
    free(xpath);
    if (rc != SR_ERR_OK) {
        return;
    }
    for (size_t i = 0; i < count; i++){
        print_val(&values[i]);
    }
    sr_free_values(values, count);
}

char *ev_to_str(sr_event_t ev)
{
    switch (ev) {
    case SR_EV_CHANGE:
        return "change";
    case SR_EV_DONE:
        return "done";
    case SR_EV_ABORT:
    default:
        return "abort";
    }
}