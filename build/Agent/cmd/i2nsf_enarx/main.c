#include "trust_handler.h"
#include "log.h"


int main(void)
{
    return (0);
}



extern char* handle_message_trusted(char* data) {
    // function implementation
    return handle_message(data);
}


int log_set_level_trusted(int level) {
    // function implementation
    log_set_level(level);
}
