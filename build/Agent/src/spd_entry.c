
#include "spd_entry.h"


#define MAX_PATH  200
#define MAX_IP 40
#define MAX_KEY 1024

spd_entry_node* create_spd_node(){
	spd_entry_node *spd_node = (spd_entry_node *) malloc(sizeof(struct spd_entry_node));
	spd_node->name = (char *) malloc(sizeof(char) * MAX_PATH);
	spd_node->index = 0;
    // Direction of the tunnel
	spd_node->policy_dir = 0;
	spd_node->req_id = 0;
	spd_node->local_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	spd_node->remote_subnet = (char *) malloc(sizeof(char) * MAX_IP); 
	spd_node->tunnel_local = (char *) malloc(sizeof(char) * MAX_IP); 
    spd_node->tunnel_remote = (char *) malloc(sizeof(char) * MAX_IP); 
    spd_node->inner_protocol = 0;
    spd_node->srcport = 0;
    spd_node->dstport = 0;
    spd_node->action = 0;
    spd_node->ext_seq_num =false;
    spd_node->seq_overflow = false;
    spd_node->ipsec_mode = 0;
    spd_node->protocol_parameters = 0;
    spd_node->integrity_alg = 0;
    spd_node->encryption_alg = 0;
    spd_node->anti_replay_window = 0;
    spd_node->pfp_flag = false;
    spd_node->stateful_frag_check = false;
    spd_node->bypass_dscp = false;
    spd_node->ecn = false;
    spd_node->tfc_pad = false;
    spd_node->df_bit = 0;
    spd_node->next=NULL;
    return spd_node;
}