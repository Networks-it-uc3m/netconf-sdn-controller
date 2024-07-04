#include "sysrepo_entries.h"

sad_entry_node *init_sad_node = NULL;
spd_entry_node* init_spd_node = NULL;


pthread_mutex_t sad_entries_locker =PTHREAD_MUTEX_INITIALIZER; 

// FROM spd_entry.c
void add_spd_node(spd_entry_node* node_entry){
	if (init_spd_node == NULL) {
		init_spd_node=node_entry;
		node_entry->next=NULL;
	} else {
		spd_entry_node *node = init_spd_node;
		while(node->next != NULL)
			node=node->next;
		node->next=node_entry;
	}
}

// for case 1
void show_spd_list(){
	
	spd_entry_node *node = init_spd_node;
	INFO("NAME --- INDEX --- REQ_ID --- SRC --- DST --- DIRECTION --- PROTOCOL --- MODE");
	while (node != NULL){
		INFO("%s --- %d --- %d --- %s --- %s --- %d --- %d ", node->name, node->index, node->req_id, node->local_subnet, node->remote_subnet, node->policy_dir,
			node->ipsec_mode);
		node=node->next;
	}
}

spd_entry_node *get_spd_node(char *name){

    spd_entry_node *node = init_spd_node;
	while (node != NULL) {
		if (!strcmp(node->name, name)) {
			return node;
		} else {
			node = node->next;
		}
	}
	
	return NULL;
}

spd_entry_node* get_spd_node_by_index(int policy_index){

    spd_entry_node *node = init_spd_node;
	while (node != NULL) {
		if (node->index == policy_index) {
			return node;
		} else {
			node = node->next;
		}
	}
	
	return NULL;
}



void free_spd_node(spd_entry_node * n) {
	
    if (n != NULL) {  
        free (n);
    } 
}

int del_spd_node(char *name) {

    spd_entry_node *node = init_spd_node;
    if (node != NULL) {
		
        spd_entry_node *prev_node = NULL;
        prev_node = create_spd_node();

        while (strcmp(name,node->name)) {
            prev_node = node;
            node = node->next;
        }
        if (node == init_spd_node){
            init_spd_node = init_spd_node->next;
            free_spd_node(prev_node);
        }
        else if (!strcmp(name,node->name)) {
            prev_node->next = node->next;
            free_spd_node(node);
        }
		
    } else return SR_ERR_OPERATION_FAILED;

    return SR_ERR_OK;
}


int readSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,spd_entry_node *spd_node, int case_value) {

    int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_val_t *value = NULL;
    sr_change_oper_t oper;
    char  *name = NULL;

    DBG("**SPD READ.... ");

        rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
        if (SR_ERR_OK != rc)
            return SR_ERR_VALIDATION_FAILED;
        do {
        	
            if (oper == SR_OP_CREATED) value = new_value;
            else value = old_value;
			
            if (0 == strncmp(value->xpath, xpath,strlen(xpath))) {

                name = strrchr(value->xpath, '/');
				
				//DBG("name to be found: %s", name);
				
				//<direction>inbound</direction>
	            if (0 == strcmp("/direction", name)) {
	                    if (!strcmp(value->data.string_val, "outbound"))
	                        spd_node->policy_dir = IPSEC_DIR_OUTBOUND;
	                    else if (!strcmp(value->data.string_val, "inbound"))
	                        spd_node->policy_dir = IPSEC_DIR_INBOUND;
	                    else {
	                        rc = SR_ERR_VALIDATION_FAILED;    
	                        ERR("spd-entry Bad direction: %s", sr_strerror(rc));
	                        return rc;
	                    }
	                    DBG("direction: %hu",spd_node->policy_dir);
	            }
				
				
				//<reqid>1</reqid>
	            else if (0 == strcmp("/reqid", name)) {
						spd_node->req_id = value->data.uint64_val;
	                    DBG("reqid: %llu",spd_node->req_id);
	            }
				
				//<anti-replay-window>32</anti-replay-window>
	            else if (0 == strcmp("/anti-replay-window", name)) {
						spd_node->anti_replay_window = value->data.uint64_val;
	                    DBG("anti_replay_window: %llu",spd_node->anti_replay_window);
	            }
				
				//<local-subnet>2001:DB8:123::200/128</local-subnet>
				else if (0 == strcmp("/local-prefix", name)) {
					strcpy(spd_node->local_subnet,value->data.string_val);
                    DBG("local-prefix: %s",spd_node->local_subnet);
				}
				
				
				//<remote-subnet>2001:DB8:123::100/128</remote-subnet>
				else if (0 == strcmp("/remote-prefix", name)) {
					strcpy(spd_node->remote_subnet,value->data.string_val);
                    DBG("remote-prefix: %s",spd_node->remote_subnet);
				}
				
				//<inner-protocol>any</inner-protocol>
				else if (0 == strcmp("/inner-protocol", name)) {
					spd_node->inner_protocol = value->data.uint16_val;
					if (spd_node->inner_protocol < 0 || spd_node->inner_protocol > 256) {
						if (!strcmp(value->data.string_val, "any"))
							spd_node->inner_protocol = 256;
				    	else {
							DBG("Error in inner-protocol value: %u",spd_node->inner_protocol);
	                        rc = SR_ERR_VALIDATION_FAILED;
	                        break;
						}
					}
					DBG("inner-protocol: %i",spd_node->inner_protocol);
				}
				
				else if (0 == strncmp("/start", name,strlen("/start"))) {
	                    if (NULL != strstr(value->xpath,"/local-ports")) {
	                        spd_node->srcport = value->data.uint16_val;
							DBG("local-port start: %u",spd_node->srcport);
						}
						if (NULL != strstr(value->xpath,"/remote-ports")) {
	                        spd_node->dstport = value->data.uint16_val;
	                        DBG("remote-port start: %u",spd_node->dstport);
	                    }
				}
				//<action>protect</action>
	            else if (0 == strcmp("/action", name)) {
	                    if (!strcmp(value->data.string_val, "protect"))
	                        spd_node->action =  IPSEC_POLICY_PROTECT;
	                    else if (!strcmp(value->data.string_val, "bypass"))
	                        spd_node->action = IPSEC_POLICY_BYPASS;
	                    else if (!strcmp(value->data.string_val, "discard"))
	                        spd_node->action = IPSEC_POLICY_DISCARD;
	                    else {
	                        rc = SR_ERR_VALIDATION_FAILED;    
	                        ERR("spd-entry Bad action (%s): %s",value->data.string_val, sr_strerror(rc));
	                        return rc;
	                    }
	                    DBG("action: %i",spd_node->action);
	            }
				
                //<ext-seq-num>true</ext-seq-num>
				else if (0 == strcmp("/ext-seq-num", name)) {
					spd_node->ext_seq_num = value->data.bool_val;
					DBG("ext-seq-num: %i",spd_node->ext_seq_num);
				}
                
				//<seq-overflow>true</seq-overflow>
				else if (0 == strcmp("/seq-overflow", name)) {
					spd_node->seq_overflow = value->data.bool_val;
					DBG("seq-overflow: %i",spd_node->seq_overflow);
				}
				
				//<pfp-flag>false</pfp-flag>
				else if (0 == strcmp("/pfp-flag", name)) {
					spd_node->pfp_flag = value->data.bool_val;
					DBG("pfp-flag: %i",spd_node->pfp_flag);
				}
				//<stateful-frag-check>false</stateful-frag-check>
				else if (0 == strcmp("/stateful-frag-check", name)) {
					spd_node->stateful_frag_check = value->data.bool_val;
					DBG("stateful-frag-check: %i",spd_node->stateful_frag_check);
				}
				
				//<mode>transport</mode>
	            else if (0 == strcmp("/mode", name)) {
	                if (!strcmp(value->data.string_val, "transport")){
	                    spd_node->ipsec_mode = IPSEC_MODE_TRANSPORT;
	                }
	                else if (!strcmp(value->data.string_val, "tunnel")) {
	                    spd_node->ipsec_mode = IPSEC_MODE_TUNNEL; 

	                }
	                DBG("mode: %hu", spd_node->ipsec_mode);
	            }
				
				else if (0 == strcmp("/local", name)) {
					strcpy(spd_node->tunnel_local,value->data.string_val);
                    DBG("tunnel_local: %s",spd_node->tunnel_local);
				}
				else if (0 == strcmp("/remote", name)) {
					strcpy(spd_node->tunnel_remote,value->data.string_val);
                    DBG("tunnel_remote: %s",spd_node->tunnel_remote);
				}
				else if (0 == strcmp("/bypass-dscp", name)) {
					spd_node->bypass_dscp = value->data.bool_val;
					DBG("bypass: %i",spd_node->bypass_dscp);
				}
				else if (0 == strcmp("/ecn", name)) {
					spd_node->ecn = value->data.bool_val;
					DBG("ecn: %i",spd_node->ecn);
				}
	            else if (0 == strcmp("/df-bit", name)) {
	                if (!strcmp(value->data.string_val, "clear")){
	                    spd_node->df_bit = IPSEC_DF_BIT_CLEAR;
	                }
	                else if (!strcmp(value->data.string_val, "set")) {
	                    spd_node->df_bit = IPSEC_DF_BIT_SET;
	                }
	                else if (!strcmp(value->data.string_val, "copy")) {
	                    spd_node->df_bit = IPSEC_DF_BIT_COPY;
	                }
	                DBG("df-bit: %hu", spd_node->df_bit);
	            }

				
				//<protocol-parameters>esp</protocol-parameters>
	            else if (0 == strcmp("/protocol-parameters", name)) {
	            	if (!strcmp(value->data.string_val, "esp"))
	                	spd_node->protocol_parameters =  IPSEC_PROTO_ESP;
	                DBG("protocol-parameters: %hu",spd_node->protocol_parameters);
	            }
				
				// integrity and encryption are defined as list, list are not supported yet. TBD
	           	else if (NULL != strstr(name,"/integrity")) {
	            		spd_node->integrity_alg = value->data.int16_val;
	                	DBG("integrity: %i",spd_node->integrity_alg);
	            }
	           	else if (NULL != strstr(name,"/encryption")) {
	            		spd_node->encryption_alg = value->data.int16_val;
	                	DBG("encryption: %i",spd_node->encryption_alg);
	            }
				//tfc-pad
				else if (0 == strcmp("/tfc-pad", name)) {
					spd_node->tfc_pad = value->data.bool_val;
					DBG("tfc-pad: %i",spd_node->tfc_pad);
				}
				
				
				//spd-mark TBD
				
				// fin v8
				
            } else break;
             
            sr_free_val(old_value);
            sr_free_val(new_value);

        } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_value, &new_value));

    return rc;
}



int addSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *spd_name, int case_value) {

	int rc = SR_ERR_OK;

	DBG("**ADD/MOD SPD %s with name: %s",xpath, spd_name);

	if (get_spd_node(spd_name) != NULL) {
		DBG("ADD SPD entry %s, already exists!", spd_name);
		return rc;
	}

	spd_entry_node *spd_node = create_spd_node();
	strcpy(spd_node->name,spd_name);
	rc = readSPD_entry(sess,it,xpath,spd_node,case_value);
	if (rc != SR_ERR_OK) {
		ERR("ADD SPD in getSDP_entry: %s", sr_strerror(rc));
		return rc;
	}

	add_spd_node(spd_node);
 
    //    return SR_ERR_OK;
	//} else {
    if (case_value == 2) {
		
        rc = pf_addpolicy(spd_node);    
        if (SR_ERR_OK != rc) {
            ERR("ADD SPD in getSDP_entry: %s", sr_strerror(rc));
            return rc;     
        }
		// if inbound, forward policy in linux system has to be created
		if (spd_node->policy_dir == IPSEC_DIR_INBOUND) {						
			#ifdef _WIN32
			    DBG("Windows");
			#elif __linux__
			    DBG("Linux System detected!");
				spd_node->policy_dir = IPSEC_DIR_FORWARD;
				rc = pf_addpolicy(spd_node); 
				spd_node->policy_dir = IPSEC_DIR_INBOUND;
		        if (SR_ERR_OK != rc) {
		            ERR("ADD SPD forward policy: %s", sr_strerror(rc));
		            return rc;     
		        }	
			#elif __unix__
			    DBG("Other unix OS");
			#else
			    DBG("Unidentified OS");
			#endif	
		}
	}
    
    INFO("SPD entry added: REQID %d",spd_node->req_id);
    show_spd_list();
	

    return SR_ERR_OK;
}

int removeSPD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *spd_name, int case_value) {

    int rc = SR_ERR_OK;  

	if (case_value == 1) {
		ERR("Remove SPD entry for case 1 not supported yet !!");
	} else { 	
	
		DBG("Remove SPD entry for case 2 %s:", spd_name);

        spd_entry_node *node = get_spd_node(spd_name);
		
        if (node != NULL) {
            rc = pf_delpolicy(node);
	
			// if inbound, forward policy in linux system has to be created
			if (node->policy_dir == IPSEC_DIR_INBOUND) {						
				#ifdef _WIN32
				    DBG("Windows");
				#elif __linux__
				    DBG("Linux System detected!");
					node->policy_dir = IPSEC_DIR_FORWARD;
					rc = pf_delpolicy(node); 
					node->policy_dir = IPSEC_DIR_INBOUND;
			        if (SR_ERR_OK != rc) {
			            ERR("Remove SPD forward policy: %s", sr_strerror(rc));
			            return rc;     
			        }	
				#elif __unix__
				    DBG("Other unix OS");
				#else
				    DBG("Unidentified OS");
				#endif	
			}			

            if (SR_ERR_OK != rc){
                ERR("Remove SPD in pfkeyv2_delpolicy: %s", sr_strerror(rc));
            } else {
                rc = del_spd_node(spd_name);
                if (rc != SR_ERR_OK) {
                    ERR("Remove SPD entry in del_spd_node: %s", sr_strerror(rc));
                } else rc = SR_ERR_OK;
            }
        } else{
            rc = 0;
			// TODO do not return error so Sysrepo can at least clean the db
            ERR("Remove SPD, policy not found: %s",sr_strerror(rc));
        }		
	}
    show_spd_list();
	
	return rc;

}

#ifdef Enarx
// From sad_entry.c
void add_sad_node_enarx(sad_entry_node* node_entry){

	// We need to add the node_entry into the enarx client
	// It will return a new sad_entry_node whith the decrypted contents and an entryid
	sad_entry_node* rec_entry = create_sad_node();
	// We may change the method in a future, so we dont need to malloc more data
	if (add_trusted_sad_entry(rec_entry, node_entry) != 0) {
		ERR("Couldnt add sad_entry node");
		free(rec_entry);
		return;
	}
	strcpy(node_entry->encryption_key,rec_entry->encryption_key);
	strcpy(node_entry->integrity_key,rec_entry->integrity_key);
	free(rec_entry);
}

int del_sad_node_enarx(char *sad_name) {
	if (del_trusted_sad_entry(sad_name) != 0) {
		ERR("Error when removing sad entry %s",sad_name);
		return 1;
	}
	return 0;
}
// This is for the case we we are running the application using Enarx
// By using keystone the main idea should be the same
// -- First look for the SAD entries from sysrepo (checking local variables)
// -- Iterate over each entry:
// 		-- Ask directly to the PF_KEY managament API to request the information about that entry
// 		-- If it does not exist continue iterating (it should prompt an error). We can consider this also as en event
//      -- If the sad entry exists, we extract the information from the SADB_GET message of the PF_KEY socket
//     		-- Then we send this information to the Trusted application to verify the values
//			-- The trusted application will compare the stored sad entry and the one from the kernel are the same "compare_sad_entries"
//			-- It will return the output of this verification.
// 			-- Then this event needs to be handled by the untrusted side
// For verification of the existing sad_nodes 
void verify_sad_nodes() {
	pthread_mutex_lock(&sad_entries_locker);
	sad_entry_node *node = init_sad_node;
	while (node != NULL) {
		sad_entry_node *out_node = create_sad_node();
		if (pf_getsad(node,out_node) != 0) {
			ERR("SAD not found in kernel, probably removed");
		} else {
			strcpy(out_node->name,node->name);
			// Now lets against the trusted app
			char verify_response[32];
			int verification = verify_trusted_sad_entry(verify_response,out_node);
			switch (verification)
			{
			case 1:
				// Socket error 
				break;
			case 2:
				ERR("ALERT with %s", verify_response);
				ERR("Invalid verification of %s: SPI %d\tREQID: %d",node->name,node->spi,node->req_id);
				break;
			case 3:
				ERR("INVALID ANSWER!");
				break;
			default:
				INFO("Correct verification of %s: SPI %d\t REQID: %d",node->name,node->spi,node->req_id);
				break;
			}
		}
		node=node->next;
	}
	pthread_mutex_unlock(&sad_entries_locker);
}
#endif

	
	

void free_sad_node(sad_entry_node * n) {
    if (n != NULL) {  
        free (n);
    } 
}

int readSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,sad_entry_node *sad_node) {
    int rc = SR_ERR_OK;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    sr_val_t *value = NULL;
    sr_change_oper_t oper;
    char  *name = NULL;

    DBG("**Read SAD entry: %s",sad_node->name);
    
	rc = sr_get_change_next(sess, it, &oper, &old_value, &new_value);
    if (SR_ERR_OK != rc)
            return rc;

    do {
	    if (oper == SR_OP_CREATED) value = new_value;
        else value = old_value;

        if (0 == strncmp(value->xpath, xpath,strlen(xpath))) {
			
            name = strrchr(value->xpath, '/');
			
			//<reqid>1</reqid>
            if (0 == strcmp("/reqid", name)) {
					sad_node->req_id = value->data.uint64_val;
                    DBG("reqid: %llu",sad_node->req_id);
            }
			//<spi>34501</spi>
            else if (0 == strcmp("/spi", name)) {
					sad_node->spi = value->data.uint32_val;
                    DBG("spi: %lu",sad_node->spi);
            }
            //<ext-seq-num>true</ext-seq-num>
			else if (0 == strcmp("/ext-seq-num", name)) {
				sad_node->ext_seq_num = value->data.bool_val;
				DBG("ext-seq-num: %i",sad_node->ext_seq_num);
			}
			
			//<seq-number-counter>100</seq-number-counter>
			// TODO maybe remove this parameter since it is not specified in the RFC
			else if (0 == strcmp("/seq-number-counter", name)) {
				sad_node->seq_number_counter = value->data.uint64_val;
				DBG("seq-number-counter: %llu",sad_node->seq_number_counter);
			}
			
			//<seq-overflow>true</seq-overflow>
			else if (0 == strcmp("/seq-overflow", name)) {
				sad_node->seq_overflow = value->data.bool_val;
				DBG("seq-overflow: %i",sad_node->seq_overflow);
			}
			
			//<anti-replay-window>32</anti-replay-window>
            else if (0 == strcmp("/anti-replay-window", name)) {
					sad_node->anti_replay_window = value->data.uint64_val;
                    DBG("anti_replay_window: %llu",sad_node->anti_replay_window);
            }
						
			//<local-subnet>2001:DB8:123::200/128</local-subnet>
			else if (0 == strcmp("/local-prefix", name)) {
				//sa_local_subnet = malloc(strlen(value->data.string_val) + 1);
				strcpy(sad_node->local_subnet,value->data.string_val);
                DBG("local-subnet: %s",sad_node->local_subnet);
			}
			
			//<remote-subnet>2001:DB8:123::100/128</remote-subnet>
			else if (0 == strcmp("/remote-prefix", name)) {
				//sa_remote_subnet = malloc(strlen(value->data.string_val) + 1);
				strcpy(sad_node->remote_subnet,value->data.string_val);
                DBG("remote-subnet: %s",sad_node->remote_subnet);
			}
			
			//<inner-protocol>any</inner-protocol>
			else if (0 == strcmp("/inner-protocol", name)) {
				sad_node->inner_protocol = value->data.uint16_val;
				if (sad_node->inner_protocol < 0 || sad_node->inner_protocol > 256) {
					if (!strcmp(value->data.string_val, "any"))
						sad_node->inner_protocol = 256;
			    	else {
						DBG("Error in inner-protocol value: %u",sad_node->inner_protocol);
                        rc = SR_ERR_VALIDATION_FAILED;
                        break;
					}
				}
				DBG("inner-protocol: %i",sad_node->inner_protocol);
			}
			
			else if (0 == strncmp("/start", name,strlen("/start"))) {
                    if (NULL != strstr(value->xpath,"/local-ports")) {
                        sad_node->srcport = value->data.uint16_val;
						DBG("local-port start: %u",sad_node->srcport);
					}
					if (NULL != strstr(value->xpath,"/remote-ports")) {
                        sad_node->dstport = value->data.uint16_val;
                        DBG("remote-port start: %u",sad_node->dstport);
                    }
			}
			
			//<mode>transport</mode>
            else if (0 == strcmp("/mode", name)) {
                if (!strcasecmp(value->data.string_val, "transport")){
                    sad_node->ipsec_mode = IPSEC_MODE_TRANSPORT;
                }
                else if (!strcasecmp(value->data.string_val, "tunnel")) {
                    sad_node->ipsec_mode = IPSEC_MODE_TUNNEL; 

                }
                DBG("mode: %hu", sad_node->ipsec_mode);
            }
			
			//<tunnel>
			//	<local>192.168.123.200</local>
			//	<remote>192.168.123.100</remote>
			//	<df-bit>clear</df-bit>
			//	<bypass-dscp>true</bypass-dscp>
			//	<ecn>false</ecn>
			//</tunnel>
			else if (0 == strcmp("/local", name)) {
				//sa_tunnel_local = malloc(strlen(value->data.string_val) + 1);
				strcpy(sad_node->tunnel_local,value->data.string_val);
                DBG("tunnel_local: %s",sad_node->tunnel_local);
			}
			else if (0 == strcmp("/remote", name)) {
				//sa_tunnel_remote = malloc(strlen(value->data.string_val) + 1);
				strcpy(sad_node->tunnel_remote,value->data.string_val);
                DBG("tunnel_remote: %s",sad_node->tunnel_remote);
			}
			else if (0 == strcmp("/bypass-dscp", name)) {
				sad_node->bypass_dscp = value->data.bool_val;
				DBG("bypass: %i",sad_node->bypass_dscp);
			}
			else if (0 == strcmp("/ecn", name)) {
				sad_node->ecn = value->data.bool_val;
				DBG("ecn: %i",sad_node->ecn);
			}
            else if (0 == strcmp("/df-bit", name)) {
                if (!strcmp(value->data.string_val, "clear")){
                    sad_node->df_bit = IPSEC_DF_BIT_CLEAR;
                }
                else if (!strcmp(value->data.string_val, "set")) {
                    sad_node->df_bit = IPSEC_DF_BIT_SET;
                }
                else if (!strcmp(value->data.string_val, "copy")) {
                    sad_node->df_bit = IPSEC_DF_BIT_COPY;
                }
                DBG("df-bit: %hu", sad_node->df_bit);
            }
			
					
			//<protocol-parameters>esp</protocol-parameters>
            else if (0 == strcmp("/protocol-parameters", name)) {
            	if (!strcmp(value->data.string_val, "esp"))
                	sad_node->protocol_parameters =  IPSEC_PROTO_ESP;
                DBG("protocol-parameters: %hu",sad_node->protocol_parameters);
            }
			
			// integrity and encryption are defined as list, list are not supported yet. TBD
            else if (0 == strcmp("/encryption-algorithm", name)) {
            	sad_node->encryption_alg = value->data.int16_val;
                DBG("encryption: %i",sad_node->encryption_alg);
            }
            else if (0 == strcmp("/iv", name)) {


				remove_colon(sad_node->encryption_iv,value->data.string_val);
                DBG("encryption iv: %s",sad_node->encryption_iv);
            }
			else if (0 == strncmp("/key-length", name,strlen("/key-length"))) {
				sad_node->encryption_key_length = value->data.uint16_val;
				DBG("encryption key length: %d",sad_node->encryption_key_length);
			}
			else if (0 == strncmp("/key", name,strlen("/key"))) {

                    if (NULL != strstr(value->xpath,"/encryption")) {
							remove_colon(sad_node->encryption_key,value->data.string_val);
						DBG("encryption_keyt: %s",sad_node->encryption_key);
					}
					if (NULL != strstr(value->xpath,"/integrity")) {
						remove_colon(sad_node->integrity_key,value->data.string_val);
                        DBG("integrity_key: %s",sad_node->integrity_key);
                    }
			}
            else if (0 == strcmp("/integrity-algorithm", name)) {
            	sad_node->integrity_alg = value->data.int16_val;
                DBG("integrity: %i",sad_node->integrity_alg);
            }
			
			else if (0 == strcmp("/local", name)) {
				//sa_tunnel_local = value->data.string_val;
				strcpy(sad_node->tunnel_local,value->data.string_val);
                DBG("tunnel_local: %s",sad_node->tunnel_local);
			}
			else if (0 == strcmp("/remote", name)) {
				//sa_tunnel_remote = value->data.string_val;
				strcpy(sad_node->tunnel_remote,value->data.string_val);
                DBG("tunnel_remote: %s",sad_node->tunnel_remote);
			}
			else if (0 == strcmp("/bypass-dscp", name)) {
				sad_node->bypass_dscp = value->data.bool_val;
				DBG("bypass: %i",sad_node->bypass_dscp);
			}
			else if (0 == strcmp("/ecn", name)) {
				sad_node->ecn = value->data.bool_val;
				DBG("ecn: %i",sad_node->ecn);
			}
            else if (0 == strcmp("/df-bit", name)) {
                if (!strcmp(value->data.string_val, "clear")){
                    sad_node->df_bit = IPSEC_DF_BIT_CLEAR;
                }
                else if (!strcmp(value->data.string_val, "set")) {
                    sad_node->df_bit = IPSEC_DF_BIT_SET;
                }
                else if (!strcmp(value->data.string_val, "copy")) {
                    sad_node->df_bit = IPSEC_DF_BIT_COPY;
                }
                DBG("df-bit: %hu", sad_node->df_bit);
            }
			
			// SOFT and HARD lifetime related stuff
            else if (0 == strcmp("/time", name)) {
                if (NULL != strstr(value->xpath,"/sa-lifetime-soft")) { 
                    sad_node->lft_time_soft = value->data.int32_val;
                    DBG("lifetime time-soft: %lu",sad_node->lft_time_soft);
                } else if (NULL != strstr(value->xpath,"/sa-lifetime-hard")) { 
                    sad_node->lft_time_hard= value->data.int32_val;
                    DBG("lifetime time-hard: %lu",sad_node->lft_time_hard);
                }
            }  
            else if (0 == strcmp("/bytes", name)) {
                if (NULL != strstr(value->xpath,"/sa-lifetime-soft")) { 
                    sad_node->lft_bytes_soft = value->data.int32_val;
                    DBG("lifetime bytes-soft: %lu",sad_node->lft_bytes_soft);
                } else if (NULL != strstr(value->xpath,"/sa-lifetime-hard")) { 
                    sad_node->lft_bytes_hard = value->data.int32_val;
                    DBG("lifetime bytes-hard: %i",sad_node->lft_bytes_hard);
                }
            }  
            else if (0 == strcmp("/packets", name)) {
                if (NULL != strstr(value->xpath,"/sa-lifetime-soft")) { 
                    sad_node->lft_packets_soft = value->data.int32_val;
                    DBG("lifetime packets-soft: %lu",sad_node->lft_packets_soft);
                } else if (NULL != strstr(value->xpath,"/sa-lifetime-hard")) {  
                    sad_node->lft_packets_hard = value->data.int32_val;
                    DBG("lifetime packets-hard: %i",sad_node->lft_packets_hard);
                }  
            }  
            else if (0 == strcmp("/idle", name)) {
                if (NULL != strstr(value->xpath,"/sa-lifetime-soft")) { 
                    sad_node->lft_idle_soft = value->data.int32_val;
                    DBG("lifetime time-idle-soft: %i",sad_node->lft_idle_soft);
                } else if (NULL != strstr(value->xpath,"/sa-lifetime-hard")) {  
                    sad_node->lft_idle_hard= value->data.int32_val;
                    DBG("lifetime time-idle-hard: %i",sad_node->lft_idle_hard);
                }  
            } 

			// TODO we need to add action option 
								
			
        } else break;
            
	    sr_free_val(old_value);
        sr_free_val(new_value);

    } while (SR_ERR_OK == sr_get_change_next(sess, it,&oper, &old_value, &new_value));

	    return SR_ERR_OK;
}

int addSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *sad_name) {
    int rc = SR_ERR_OK;
    //spi = atoi(spi_number);
    DBG("**ADD SAD entry: %s",sad_name);
	sad_entry_node *sad_node = create_sad_node();
	strcpy(sad_node->name,sad_name);
	pthread_mutex_lock(&sad_entries_locker);
    rc = readSAD_entry(sess,it,xpath,sad_node);
    if (rc != SR_ERR_OK) {
        ERR("ADD SAD in getSAD_entry: %s",sr_strerror(rc));
		pthread_mutex_unlock(&sad_entries_locker);
        return rc;
    }
	// Store locally the sad_entry but with the encrypted keys
    add_sad_node(&init_sad_node,sad_node);
	#ifdef Enarx
		// TODO change this to make a copy of the node_entry so we dont store in the Untrusted Part of the application
		// they original keys. 
		add_sad_node_enarx(sad_node);
	#endif
    rc = pf_addsad(sad_node);
    if (SR_ERR_OK != rc) {
        ERR("ADD SAD in getSAD_entry: %s", sr_strerror(rc));
		pthread_mutex_unlock(&sad_entries_locker);
        return rc;     
    }

    INFO("SAD entry added: REQID: %d \t SPI: %d",sad_node->req_id,sad_node->spi);
    show_sad_list(init_sad_node);
	pthread_mutex_unlock(&sad_entries_locker);
    return SR_ERR_OK;

}



int send_acquire_notification(sr_session_ctx_t *session, int policy_index){

    int rc = SR_ERR_OK;
    /*sr_val_t *input = NULL;
    size_t input_cnt = 0;*/
    char full_xpath[MAX_PATH];
    char tmp_xpath[MAX_PATH];
	 
    
	DBG ("send_acquire_notification for policy %i:", policy_index);	
	
	sr_conn_ctx_t *connection = NULL;
	struct lyd_node *notif = NULL;
	const struct ly_ctx *ctx;
	const char *path = "/ietf-i2nsf-ikeless:sadb-acquire";
	const char *node_path = NULL, *node_val;
	
	connection = sr_session_get_connection(session); 
	
	ctx = sr_acquire_context(connection);
	
	/* create the notification */
    lyd_new_path(notif, ctx, path, NULL, 0, 0);
    if (!notif) {
        ERR("Creating notification \"%s\" failed.\n", path);
        goto cleanup;
    }
	
	
	spd_entry_node* spd_node = get_spd_node_by_index(policy_index);
    if (spd_node != NULL) {
		
	    if (!lyd_new_path(notif, NULL, "/ietf-i2nsf-ikeless:sadb-acquire/ipsec-policy-name", spd_node->name, 0, 0)) {
	    	DEBUG("Creating value \"%s\" failed.\n", spd_node->name);
	        goto cleanup;
	    }
		
	    if (!lyd_new_path(notif, NULL, "/ietf-i2nsf-ikeless:sadb-acquire/traffic-selector/local-subnet", spd_node->local_subnet, 0, 0)) {
	    	DEBUG("Creating value \"%s\" failed.\n", spd_node->name);
	        goto cleanup;
	    }
		
	    if (!lyd_new_path(notif, NULL, "/ietf-i2nsf-ikeless:sadb-acquire/traffic-selector/remote-subnet", spd_node->remote_subnet, 0, 0)) {
	    	DEBUG("Creating value \"%s\" failed.\n", spd_node->name);
	        goto cleanup;
	    }
		
	    /* send the notification */
	    rc = sr_notif_send_tree(session, notif,0,0);
	    if (rc != SR_ERR_OK) {
	        goto cleanup;
	    }
		
	} else {
		INFO("send acquire notification: policy not found: %s", policy_index);
	}
	
	lyd_free_all(notif);

	
	return rc;	
	
cleanup:
    lyd_free_all(notif);
	if (ctx) {
        sr_release_context(connection);
    }
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

int removeSAD_entry(sr_session_ctx_t *sess, sr_change_iter_t *it,char *xpath,char *sad_name) {
    int rc = SR_ERR_OK;
    pthread_mutex_lock(&sad_entries_locker);
    DBG("SAD entry REMOVE: %s",sad_name);
	sad_entry_node *node = get_sad_node(&init_sad_node, sad_name);
    if (node != NULL) {
        rc = pf_delsad(node);
        if (SR_ERR_OK != rc){
            ERR("Remove SAD in pfkeyv2_delsad: %s",sr_strerror(rc));
            rc = SR_ERR_OPERATION_FAILED;
        } else {
            rc = del_sad_node(&init_sad_node, sad_name);
            if (rc != SR_ERR_OK) {
                ERR("Remove SAD entry in del_sad_node: %s",sr_strerror(rc));
                rc = SR_ERR_OPERATION_FAILED;
            } else rc = SR_ERR_OK;

			#ifdef Enarx
				del_sad_node_enarx(sad_name);
				// TODO Atm we skip this error, but it should be returned
			#endif
        }

    } else{
        rc = SR_ERR_OPERATION_FAILED;
        ERR("Remove SAD, spi not found: %s",sr_strerror(rc));
    }
	
	pthread_mutex_unlock(&sad_entries_locker);
		

    show_sad_list(init_sad_node);
    return rc;
}

int send_sa_expire_notification(sr_session_ctx_t *session, unsigned long int spi, bool soft){


    int rc = SR_ERR_OK;
    /*sr_val_t *input = NULL;
    size_t input_cnt = 0;*/
    char full_xpath[MAX_PATH];
    char tmp_xpath[MAX_PATH];
	 
    
	DBG ("send_expire_notification for spi: %i", spi);	
	
	sr_conn_ctx_t *connection = NULL;
	struct lyd_node *notif = NULL;
	const struct ly_ctx *ctx;
	const char *path = "/ietf-i2nsf-ikeless:sadb-expire";
	const char *node_path = NULL, *node_val;
	
	if (session == NULL) {
		ERR("Sesssion is NULL");
	}

	connection = sr_session_get_connection(session); 
	
	if (connection == NULL) {
		ERR("Error obtaining connection");
	}

	ctx = sr_acquire_context(connection);

	if (ctx == NULL) {
		ERR("Error obtaining ctx");
	}
	// ly_verb(LY_LLDBG);
	/* create the notification */
	// lyd_new_path(notif, ctx, path, NULL, 0, 0);
	pthread_mutex_lock(&sad_entries_locker);
    if (lyd_new_path(NULL, ctx, path, NULL, 0, &notif)) {
        ERR("Creating notification \"%s\" failed.\n", path);
        goto cleanup;
    }
    if (!notif) {
        ERR("Creating notification \"%s\" failed.\n", path);
        goto cleanup;
    }
	INFO("Creating notification \"%s\"\n", path);
	sad_entry_node* sad_node = get_sad_node_by_spi(&init_sad_node,spi);
    if (sad_node != NULL) {
		
	    if (lyd_new_path(notif, NULL, "/ietf-i2nsf-ikeless:sadb-expire/ipsec-sa-name", sad_node->name, 0, NULL)) {
	    	DEBUG("Creating value \"%s\" failed.\n", sad_node->name);
	        goto cleanup;
	    }
		
	    if (lyd_new_path(notif, NULL, "/ietf-i2nsf-ikeless:sadb-expire/soft-lifetime-expire", soft ? "true" : "false", 0, 0)) {
	    	DEBUG("Creating value \"%s\" failed.\n", sad_node->name);
	        goto cleanup;
		}
		
	    /* send the notification */
	    rc = sr_notif_send_tree(session, notif,0,0);
	    if (rc != SR_ERR_OK) {
	        goto cleanup;
	    }
		
	} else {
		INFO("send expire notification: spi not found: %i", spi);
		rc = SR_ERR_NOT_FOUND; 
	}
	
    lyd_free_all(notif);
    //sr_disconnect(connection);
	pthread_mutex_unlock(&sad_entries_locker);
	return rc;	
	
cleanup:
	pthread_mutex_unlock(&sad_entries_locker);
	// sr_release_context(ctx);
    lyd_free_all(notif);
    //sr_disconnect(connection);
	if (ctx) {
        sr_release_context(connection);
    }
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
	//return rc;
		
}

int send_delete_SAD_request(unsigned long int spi) {

    char xpath[MAX_PATH] = "";
    int rc = SR_ERR_OK;
    
	sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *session = NULL;
    DBG("Connect to sysrepo %i",rc);
    rc = sr_connect(0, &conn);
    if (SR_ERR_OK != rc) {
        ERR("Error by sr_connect: %s", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, &session);
    if (SR_ERR_OK != rc) {
        ERR( "Error by sr_session_start: %s", sr_strerror(rc));
        goto cleanup;
    }
	
	pthread_mutex_lock(&sad_entries_locker);
	sad_entry_node* sad_node = get_sad_node_by_spi(&init_sad_node,spi);
	if (sad_node == NULL) {
		INFO("SAD entry with SPI %d already deleted or does not exists",spi);
		goto cleanup;
	}


    sprintf(xpath, "/ietf-i2nsf-ikeless:ipsec-ikeless/sad/sad-entry[name='%s']", sad_node->name);
    DBG("removeSADbySPI xpath: %s", xpath);
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
    if (SR_ERR_OK != rc) {
        ERR("sr_delete_item: %s", sr_strerror(rc));
		pthread_mutex_unlock(&sad_entries_locker);
        goto cleanup;
    }
    rc =  sr_apply_changes(session,0);
    if (SR_ERR_OK != rc) {
		// Sometimes there is a condition race in here where the entry has already been removed from the sysrepo datastore.
        ERR("sr_commit: %s", sr_strerror(rc));
		// pthread_mutex_unlock(&sad_entries_locker);
        // goto cleanup;
    }
	#ifdef Enarx
		del_sad_node_enarx(sad_node->name);
	#endif
	del_sad_node(&init_sad_node,sad_node->name);
	pthread_mutex_unlock(&sad_entries_locker);

	if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != conn) {
        // sr_disconnect(conn);
    }
	return rc ? EXIT_FAILURE : EXIT_SUCCESS;

cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != conn) {
        // sr_disconnect(conn);
    }
}






