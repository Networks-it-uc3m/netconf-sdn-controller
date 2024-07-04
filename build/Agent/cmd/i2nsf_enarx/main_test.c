#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "sad_entry.h"
#include "log.h"
#include "utils.h"
#include "messages.h"
#include "spd_entry.h"

#include <stdio.h> 
#include <stdlib.h> 
#include <errno.h> 
// #include <netdb.h> 
#include <sys/types.h> 
// #include <netinet/in.h> 
// #include <sys/socket.h> 
// #include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include "map.h"
#include "trust_handler.h"
#define MAX 80
typedef unsigned char BYTE;

// void *run_server(void *vargp) {
//     int socket_desc, client_sock, client_size;
//     struct sockaddr_in server_addr, client_addr;
//     char server_message[2000], client_message[2000];
    
//     // Clean buffers:
//     memset(server_message, '\0', sizeof(server_message));
//     memset(client_message, '\0', sizeof(client_message));
    
//     // Create socket:
//     socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    
//     if(socket_desc < 0){
//         printf("Error while creating socket\n");
//         return -1;
//     }
//     printf("Socket created successfully\n");
    
//     // Set port and IP:
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_port = htons(4444);
//     server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
//     // Bind to the set port and IP:
//     if(bind(socket_desc, (struct sockaddr*)&server_addr, sizeof(server_addr))<0){
//         printf("Couldn't bind to the port\n");
//         return -1;
//     }
//     printf("Done with binding\n");
    
//     // Listen for clients:
//     if(listen(socket_desc, 1) < 0){
//         printf("Error while listening\n");
//         return -1;
//     }
//     printf("\nListening for incoming connections.....\n");
    
//     // Accept an incoming connection:
//     client_size = sizeof(client_addr);
//     client_sock = accept(socket_desc, (struct sockaddr*)&client_addr, &client_size);
    
//     if (client_sock < 0){
//         printf("Can't accept\n");
//         return -1;
//     }
//     printf("Client connected at IP: %s and port: %i\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
//     // Receive client's message:
//     if (recv(client_sock, client_message, sizeof(client_message), 0) < 0){
//         printf("Couldn't receive\n");
//         return -1;
//     }
//     printf("Msg from client: %s\n", client_message);
    
//     // Respond to client:
//     strcpy(server_message, "This is the server's message.");
    
//     if (send(client_sock, server_message, strlen(server_message), 0) < 0){
//         printf("Can't send\n");
//         return -1;
//     }
    
//     // Closing the socket:
//     close(client_sock);
//     close(socket_desc);
    
//     return 0;
// }

// void string2ByteArray(char* input, BYTE* output)
// {
//     int loop;
//     int i;
    
//     loop = 0;
//     i = 0;
    
//     while(input[loop] != '\0')
//     {
//         output[i++] = input[loop++];
//     }
// }

// // void func(int sockfd, BYTE buff)
// {
//     // char buff[MAX];
//     int n;
//     for (;;) {
//         write(sockfd, buff, sizeof(buff));
//         bzero(buff, sizeof(buff));
//         read(sockfd, buff, sizeof(buff));
//         printf("From Server : %s", buff);
//         if ((strncmp(buff, "exit", 4)) == 0) {
//             printf("Client Exit...\n");
//             break;
//         }
//     }
// }
 


int main(void) {
        char *name = "aaa";
    char local_subnet[MAX_IP] = "10.0.0.0/24";
    char remote_subnet[MAX_IP] = "11.0.0.0/24";
    char tunnel_local[MAX_IP] = "10.0.0.61";
    char tunnel_remote[MAX_IP] = "10.0.0.228";
    long long req_id = 12;
    long spi = 0;
    char *encryption_key = "af6a404c";
    char *integrity_key = "af6a404c";
	char *encryption_iv = "af6a404c";

    sad_entry_node *sad_node = create_sad_node();

    strcpy(sad_node->name,name);
    sad_node->req_id = req_id;
    sad_node->spi = spi;
    sad_node->encryption_key = "af6a404c";
    sad_node->integrity_key = "af6a404c";
	sad_node->encryption_iv = "af6a404c"; 
    sad_node->local_subnet = local_subnet;
    sad_node->remote_subnet = remote_subnet;
    sad_node->tunnel_local = tunnel_local;
    sad_node->tunnel_remote = tunnel_remote;

    sad_entry_node *sad_node_test = (sad_entry_node*) malloc(sizeof(sad_entry_node));
    memcpy(sad_node_test,sad_node,sizeof(sad_entry_node));
    sad_node_test->encryption_key = "af6a4041";




    char *hash = get_sad_hash(sad_node);

    sad_entry_msg *message = (sad_entry_msg*) malloc(sizeof(sad_entry_msg)); 
    strcpy(message->entry_id,hash);
    message->sad_entry =  sad_node;



    // printf("Output: %s\n", serialized_msg);

    init_map();

    // Test the encoding
    JSON_Value *new_conf_msg = encode_sad_entry_msg(message);
    char *serialized_msg = encode_default_msg(10,NEW_CONFIG_MSG,new_conf_msg);
    handle_message(serialized_msg);

    // VERIFY the entries
    sad_entry_msg *ver_message = (sad_entry_msg*) malloc(sizeof(*ver_message)); 
    strcpy(ver_message->entry_id,hash);
    ver_message->sad_entry =  sad_node_test;

    // Test the encoding
    JSON_Value *new_ver_msg = encode_sad_entry_msg(ver_message);
    serialized_msg = encode_default_msg(10,REQUEST_VERIFY_MSG,new_ver_msg);
    handle_message(serialized_msg);

    // DELETE
    delete_config_msg *del_msg = (delete_config_msg*) malloc(sizeof(*del_msg)); 
    strcpy(del_msg->entry_id,hash);


    JSON_Value *del_msg_val = encode_delete_config_msg(del_msg);
    serialized_msg = encode_default_msg(10,DELETE_CONFIG_MSG, del_msg_val);
    handle_message(serialized_msg);
    
    new_conf_msg = encode_sad_entry_msg(message);
    serialized_msg = encode_default_msg(10,NEW_CONFIG_MSG,new_conf_msg);
    handle_message(serialized_msg);
    
    // exit(0);
    // default_msg *msg = malloc(sizeof(msg));
    // JSON_Object *schema = json_object(json_parse_string(serialized_msg));
    // decode_default_msg(schema, msg);
    // printf("Message code: %d\n", msg->code);
    // printf("Message work_id: %d\n", msg->work_id);
    // sad_entry_msg *config_message = malloc(sizeof(sad_entry_msg));
    // decode_sad_entry_msg(msg->data,config_message);
    // printf("entry id: %s\n",config_message->entry_id);

    // sad_entry_node *node  = config_message->sad_entry;
    // printf("Address1: %s, Address2: %s, Encryption_key: %s, Integrity_key: %s, Encryption_iv: %s\n",
    //     node->local_subnet,
    //     node->remote_subnet,
    //     node->encryption_key,
    //     node->integrity_key,
    //     node->encryption_iv);
    

    // // char hash[16];
    // // get_sad_hash(node,hash);
    // printf("hash: %s\n",hash);

    // hashmap* m = hashmap_create();

    // printf("Pointer location %p, pointer value %p\n",(void *) node,(void *) &node);
    // printf("Pointer location %d, pointer value %d\n",(u_64) node,(u_int64_t) &node);
    // printf("Pointer location %" PRIu64 ", pointer value %"PRIu64 "\n",(uint64_t )node,(uint64_t )&node);
    // hashmap_set(m,"test", sizeof("test"),(uint64_t) node);
    // uintptr_t result;
    // hashmap_get(m,"test",sizeof("test"), &result);
    // sad_entry_node *map_node = (sad_entry_node*) result;

    // m_set_sad_entry(m,hash,node);
    // sad_entry_node *map_node = m_get_sad_entry(m,hash);
    // if (map_node == NULL) {
    //     ERR("MAP_NODE does not exist");
    // } 
    // char hash2[16] = "hashtestof16byt";
    // map_node = m_get_sad_entry(m,hash2);
    // if (map_node == NULL) {
    //     ERR("MAP_NODE does not exist");
    // } 


    // printf("Address1: %s, Address2: %s, Encryption_key: %s, Integrity_key: %s, Encryption_iv: %s\n",
    //     map_node->local_subnet,
    //     map_node->remote_subnet,
    //     map_node->encryption_key,
    //     map_node->integrity_key,
    //     map_node->encryption_iv);

    // init_map();
    // sad_entry_msg *out = (sad_entry_msg*) malloc(sizeof(out));
    // if (handle_new_conf_message(msg->data,out) == 0) {
    //     INFO("NICE");
    // }else {
    //     ERR("NOT NICE");
    // ;}



    // alert_state_msg *alert_out = (alert_state_msg*) malloc(sizeof(alert_out));
    // int status = handle_request_verify_message(msg->data,alert_out);

    // if (status == 0) {
    //     INFO("Verification Succesful");
    // } else if (status == 1) {
    //     ERR("Something weird happened");
    // } else if (status == 2) {
    //     ERR("Sad entries are not equal");
    // }
    
    
    // int r = m_set_sad_entry(get_trusted_map(),hash,node);
    // if (r == 0) {
    //     ERR("WHAT1");
    // }

    // sad_entry_node *map_node = m_get_sad_entry(get_trusted_map(),hash);
    // if (map_node == 0) {
    //     ERR("MAP_NODE does not exist lul");
    // } 

    // map_node = m_get_sad_entry(get_trusted_map(),hash);
    // if (map_node == 0) {
    //     ERR("MAP_NODE does not exist lul2");
    // } 

    // delete_config_msg *delete_msg = (delete_config_msg*) malloc(sizeof(delete_msg));
    // strcpy(delete_msg->entry_id,hash);



    

    // JSON_Object *delete_object = json_value_get_object(encode_delete_config_msg(delete_msg));
    // op_result_msg *op_result = (op_result_msg*) malloc(sizeof(op_result));
    // handle_request_remove(delete_object,op_result);
    // r = m_set_sad_entry(get_trusted_map(),hash,node);
    // if (r == 0) {
    //     ERR("WHAT2");
    // }






    // json_object_clear(schema);
    // free(msg);
    // free(config_message);
    // free(out);
    // free(alert_out);

}


// int main1(void)
// {   
//     // Setup this as a global variable to exits
//     pthread_t thread_id;
//     pthread_create(&thread_id, NULL, run_server, NULL);
//     // Generate sad node for testing  
//     char *name = "aaa";
//     char local_subnet[MAX_IP] = "10.0.0.0/24";
//     char remote_subnet[MAX_IP] = "11.0.0.0/24";
//     char tunnel_local[MAX_IP] = "10.0.0.61";
//     char tunnel_remote[MAX_IP] = "10.0.0.228";
//     long long req_id = 12;
//     long spi = 0;
//     char *encryption_key = "af6a404c";
//     char *integrity_key = "af6a404c";
// 	char *encryption_iv = "af6a404c";


// 	spd_entry_node *spd_node = create_spd_node();
//     sad_entry_node *sad_node = create_sad_node();

//     strcpy(sad_node->name,name);
//     sad_node->req_id = req_id;
//     sad_node->spi = spi;
//     sad_node->encryption_key = "af6a404c";
//     sad_node->integrity_key = "af6a404c";
// 	sad_node->encryption_iv = "af6a404c";

//     char *result = serialize_sad_node(sad_node);
//     int len = strlen(result);
//     BYTE test[len];
//     string2ByteArray(result,test);

//     int sockfd, numbytes;  
//     struct hostent *he;
//     struct sockaddr_in their_addr; /* connector's address information */

//     if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
//         perror("socket");
//         exit(1);
//     }

//     their_addr.sin_family = AF_INET;      /* host byte order */
//     their_addr.sin_port = htons(4444);    /* short, network byte order */
//     their_addr.sin_addr.s_addr  = inet_addr("127.0.0.1");
//     bzero(&(their_addr.sin_zero), 8);     /* zero the rest of the struct */

//     sleep(1);

//     INFO("Connect");

//     // connect the client socket to server socket
//     if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
//         perror("connect");
//         exit(1);
//     } else {
//         printf("connected to the server..\n");
//     }

//     send(sockfd, result, strlen(result), 0);
 
//     // close the socket
//     close(sockfd);

//     pthread_join(thread_id, NULL);

// }