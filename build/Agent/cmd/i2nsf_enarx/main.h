#include "trust_handler.h"
#include "log.h"

extern char* handle_message_trusted(char* data) {
    // function implementation
    return handle_message(data);
}


int log_set_level_trusted(int level) {
    // function implementation
    log_set_level(level);
}
