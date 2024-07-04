/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pfkeyv2_entry.h"
#define MAX_IP 40
#define TRUE 1
#define FALSE 0

//int pf_register_apply(const sr_val_t *input, const size_t input_cnt, int pid);
char * pf_get_alg_enum_name(struct sadb_alg * alg, struct sadb_supported *sup);

static pthread_mutex_t pf_sadb_esp_register_run_lock = PTHREAD_MUTEX_INITIALIZER;




#define PFKEY_ALIGNMENT 8
/** aligns len to 64 bits */
#define PFKEY_ALIGN(len) (((len) + PFKEY_ALIGNMENT - 1) & ~(PFKEY_ALIGNMENT - 1))
/** calculates the properly padded length in 64 bit chunks */
#define PFKEY_LEN(len) ((PFKEY_ALIGN(len) / PFKEY_ALIGNMENT))
/** calculates user mode length i.e. in bytes */
#define PFKEY_USER_LEN(len) ((len) * PFKEY_ALIGNMENT)
/** given a PF_KEY extension this returns a pointer to the next extension */
#define PFKEY_EXT_NEXT(ext) ((struct sadb_ext*)(((char*)(ext)) + PFKEY_USER_LEN(((struct sadb_ext*)ext)->sadb_ext_len)))
/** given a PF_KEY extension this returns a pointer to the next extension also updates len (len in 64 bit words) */
#define PFKEY_EXT_NEXT_LEN(ext,len) ((len) -= (ext)->sadb_ext_len, PFKEY_EXT_NEXT(ext))
/** given a PF_KEY message header and an extension this updates the length in the header */
#define PFKEY_EXT_ADD(msg, ext) ((msg)->sadb_msg_len += ((struct sadb_ext*)ext)->sadb_ext_len)
/** given a PF_KEY message header this returns a pointer to the next extension */
#define PFKEY_EXT_ADD_NEXT(msg) ((struct sadb_ext*)(((char*)(msg)) + PFKEY_USER_LEN((msg)->sadb_msg_len)))
static inline void memwipe(void *ptr, size_t n)
{
	if (ptr)
	{
		explicit_bzero(ptr, n);
	}
}


static uint8_t proto2satype(uint8_t proto)
{
	switch (proto)
	{
		case IPPROTO_ESP:
			return SADB_SATYPE_ESP;
		case IPPROTO_AH:
			return SADB_SATYPE_AH;
		case IPPROTO_COMP:
			return SADB_X_SATYPE_IPCOMP;
		default:
			return proto;
	}
}

static void set_port(sockaddr_t *addr, uint16_t port)
{
    struct sockaddr_in *sin = (struct sockaddr_in*)addr;
    sin->sin_port = htons(port);
}


static void add_addr_ext(struct sadb_msg *msg, sad_entry_node *sad_node, uint16_t type,
						 uint8_t proto, uint8_t prefixlen, bool include_port)
{
	struct sadb_address *addr = (struct sadb_address*)PFKEY_EXT_ADD_NEXT(msg);
	size_t len;

	addr->sadb_address_exttype = type;
	addr->sadb_address_proto = proto;
	addr->sadb_address_prefixlen = prefixlen;
	// len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->inner_protocol, get_mask(sad_node->local_subnet), sad_node->srcport, get_ip(sad_node->local_subnet));
	

    
    addr->sadb_address_len = PFKEY_LEN(sizeof(*addr) + len);
	PFKEY_EXT_ADD(msg, addr);
}

static void* pf_sadb_esp_register_run(void* register_thread_info){

    char buf[4096];
	int     s, mypid;
    char *ntf = NULL;
    sr_session_ctx_t *session =NULL;
    int rc = 0;

	register_thread *info = (register_thread*) register_thread_info;
    mypid = (*info).parent_pid;
    s = (*info).socket;
    session = (*info).session;
	//pthread_mutex_lock(&sadb_register_run_lock);

	for ( ; ; ) {
        int     msglen;
        struct sadb_msg *msgp;
        msglen = Read(s, &buf, sizeof(buf));
        msgp = (struct sadb_msg *) &buf;
        
        if (msgp->sadb_msg_type == SADB_ACQUIRE) {
        	INFO("SADB_ACQUIRE received");
            print_sadb_msg(msgp,msglen);
            TRACE("print_sadb_msg sadb_esp_register_run end ..."); 
			
			msglen -= sizeof(struct sadb_msg);
		    struct sadb_ext *ext;
		    ext = (struct sadb_ext *)(msgp + 1);
			int policy_index = 0;

		    while (msglen > 0) {	
		        struct sadb_x_policy *policy;
		        struct sockaddr *sa;
		        struct sadb_address *addr;

		        switch (ext->sadb_ext_type) {
		            case SADB_X_EXT_POLICY: 
		                //policy = (struct sadb_x_sa2 *)ext;
						DBG("SADB_X_EXT_POLICY FOUND!");
		                policy = (struct sadb_x_policy *)ext;
		                policy_index = policy->sadb_x_policy_id;
						DBG("SADB_X_EXT_POLICY index: %i",policy_index);
		                break;
		        }
    
		        msglen -= ext->sadb_ext_len << 3;
		        ext = (struct sadb_ext*) ((char *)ext + (ext->sadb_ext_len << 3));
			}
            // TODO Handle this without relying in sysrepo
  		    // send_acquire_notification(session,policy_index);
        }  
	    else if (msgp->sadb_msg_type == SADB_EXPIRE) {
            INFO("SADB_EXPIRE received");
            print_sadb_msg(msgp,msglen);
            DBG("print_sadb_msg sadb_esp_register_run end");    
                // send_sa_expire_notification(session,msgp,msglen);   
            
            // if hard expire then delete SA entry in running config
            // get SPI and checks if it is hard or soft
            int spi = 0;
            bool hard = false;
            struct sadb_ext *ext;
            msglen -= sizeof(struct sadb_msg);
            ext = (struct sadb_ext *)(msgp + 1);

            // TODO understand better the composition of sadb_message. For the moment this is
            // the only way to extract the information about the 
            while (msglen > 0) {
                struct sadb_sa *sa;
                // This is not used, but I guess this should be readed below in some way
                struct sadb_lifetime *life;;

                switch (ext->sadb_ext_type) {
                    case SADB_EXT_SA: 
                        sa = (struct sadb_sa *)ext;
                        spi = ntohl(sa->sadb_sa_spi);
                        break;
                    case SADB_EXT_LIFETIME_HARD:
                        hard = true;
                        break;
                }
                msglen -= ext->sadb_ext_len << 3;
                ext = (struct sadb_ext*) ((char *)ext + (ext->sadb_ext_len << 3));
            }
			
            if (hard) {
				DBG("hard");
                // TODO Handle this without relying in Sysrepo

				if (rc == SR_ERR_OK) {
                    INFO("HARD life expire received for SPI: %d",spi);
                    rc = send_sa_expire_notification(session,spi,false); 
                	if (SR_ERR_OK == send_delete_SAD_request(spi)) {
				    	INFO("SADB_ entry delesend_delete_SAD_requestted in running: %i", spi); 
					}
				} else {
					// DBG("not remove");
				}
            } else {
				DBG("soft");
            	rc = send_sa_expire_notification(session,spi,true); 
                INFO("SOFT life expire received for SPI: %d",spi);
				if (rc != SR_ERR_OK) {
					INFO("sending soft expire notification: %i", rc);
				}
            }              
        } else {
            TRACE("Unknown SADB notification received.");
        }
        
    }
    // pthread_mutex_unlock(&pf_sadb_esp_register_run_lock);
    close(s);
    return NULL;
}

int pf_exec_register(sr_session_ctx_t *session, int satype){
	char buf[4096];
    int r;
    pthread_t pf_sadb_esp_register_run_thread;
	struct sadb_msg msg;
	int rc = SR_ERR_OK;

    DBG ("exec register form kernel IPsec messages");
    if (satype == SADB_SATYPE_ESP) {
        //DBG("pf_exec_register satype: %i", satype);
	   if (pthread_mutex_trylock(&pf_sadb_esp_register_run_lock) != 0) {
           rc = SR_ERR_OPERATION_FAILED;
	       ERR("sadb_register esp is still running: %s", sr_strerror(rc));
	       return rc;	
        }
    } else {
        rc = SR_ERR_OPERATION_FAILED;
        ERR("sadb_register error satype invalid: %s", sr_strerror(rc));
        return rc; 
    }

    int pid = getpid();
    int s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    //* Build and write SADB_REGISTER request 
    bzero(&msg, sizeof(msg));
    msg.sadb_msg_version =  PF_KEY_V2;
    msg.sadb_msg_type = SADB_REGISTER;
    msg.sadb_msg_satype = satype;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_pid = pid;
    Write(s, &msg, sizeof(msg));
	
    register_thread *info = malloc(sizeof(register_thread));
    info->socket=s;
    info->parent_pid=pid;	
	info->session=session;

	int msglen;
    struct sadb_msg *msgp;
    msglen = Read(s, &buf, sizeof(buf));
    msgp = (struct sadb_msg *) &buf;
    if (msgp->sadb_msg_pid == pid && msgp->sadb_msg_type == SADB_REGISTER) {
       	INFO("Register ok  ... ");

    }
    if (satype == SADB_SATYPE_ESP) {
        if ((r = pthread_create(&pf_sadb_esp_register_run_thread, NULL, &pf_sadb_esp_register_run, (void *)info)) != 0) {
            ERR("Unable to start sadb_esp_register thread (%s)", strerror(r));
            return SR_ERR_OPERATION_FAILED;
        }
    }
    return EXIT_SUCCESS;
}



int pf_setsadbaddr(void *p, int exttype, int protocol, int prefixlen, int port, char ip[]){
    struct sockaddr_in *addr= malloc (sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET; 
    addr->sin_port = htons(port); 
    addr->sin_addr.s_addr = inet_addr(ip);

    struct sadb_address *addrext = (struct sadb_address *) p;
    addrext->sadb_address_len = (sizeof(*addrext) + sizeof(struct sockaddr_in))/8 ;
    addrext->sadb_address_exttype = exttype;
    addrext->sadb_address_proto = protocol;
    addrext->sadb_address_prefixlen = prefixlen;
    // addrext->sadb_address_reserved = 0;
    TRACE("PF_SETSADBADDR: %d, %d, %d, %d, %s",exttype,protocol,prefixlen,port,ip);
    memcpy(addrext +1, addr, sizeof(struct sockaddr_in));
    return (addrext->sadb_address_len *8);
}





int pf_addpolicy(spd_entry_node *spd_node) {
    int s, len, error;
    char buf[PFKEY_BUFFER_SIZE], *p;
    struct sadb_msg *msg;
    // Security policy extension header specifies the way to process a traffic. this structure also includes the direction of a traffic. https://www.kame.net/newsletter/20021210/
    struct sadb_x_policy *policyext;
    struct sadb_x_ipsecrequest *req;
    char buf2[PFKEY_BUFFER_SIZE];

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version =  PF_KEY_V2;
    msg->sadb_msg_type = SADB_X_SPDADD;
	if (spd_node->protocol_parameters == IPPROTO_ESP)
    	msg->sadb_msg_satype = SADB_SATYPE_ESP;
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);
    policyext = (struct sadb_x_policy *) p;
    policyext->sadb_x_policy_len = sizeof(struct sadb_x_policy)/8;
    policyext->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policyext->sadb_x_policy_type = spd_node->action;
    policyext->sadb_x_policy_dir = spd_node->policy_dir;
    // Identifier of the kernel
    policyext->sadb_x_policy_id = spd_node->index; // doesn't work, policy_id is asigned by kernel 
    policyext->sadb_x_policy_priority =0;
	
    len += policyext->sadb_x_policy_len *8;
    p += policyext->sadb_x_policy_len *8;
    req = (struct sadb_x_ipsecrequest *) p;
    req->sadb_x_ipsecrequest_proto = spd_node->protocol_parameters;
    req->sadb_x_ipsecrequest_len = sizeof(struct sadb_x_ipsecrequest);
    req->sadb_x_ipsecrequest_mode = spd_node->ipsec_mode;
    req->sadb_x_ipsecrequest_reqid = spd_node->req_id;
	if (spd_node->req_id != 0)
    	req->sadb_x_ipsecrequest_level = IPSEC_LEVEL_UNIQUE;
	else 
		req->sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;
    len += req->sadb_x_ipsecrequest_len;
    p += req->sadb_x_ipsecrequest_len;

    if(spd_node->ipsec_mode == IPSEC_MODE_TUNNEL){
        struct sockaddr_in *src_t= malloc(sizeof(struct sockaddr_in));
        src_t->sin_family = AF_INET;
        src_t->sin_port = htons(0);
        src_t->sin_addr.s_addr = inet_addr(spd_node->tunnel_local);

        struct sockaddr_in *dst_t= malloc(sizeof(struct sockaddr_in));
        dst_t->sin_family = AF_INET;
        dst_t->sin_port = htons(0);
        dst_t->sin_addr.s_addr = inet_addr(spd_node->tunnel_remote);

        memcpy(req + 1, src_t, sizeof(struct sockaddr_in));
        memcpy((char*)(req + 1) + sizeof(struct sockaddr_in), dst_t, sizeof(struct sockaddr_in));

        req->sadb_x_ipsecrequest_len += (sizeof(struct sockaddr_in)*2);
        len += (sizeof(struct sockaddr_in)*2);
        p += (sizeof(struct sockaddr_in)*2);
    }


    policyext->sadb_x_policy_len += (req->sadb_x_ipsecrequest_len/8);
   
    int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, spd_node->inner_protocol, get_mask(spd_node->local_subnet), spd_node->srcport, get_ip(spd_node->local_subnet));
    p += src_len; len += src_len;

    int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, spd_node->inner_protocol, get_mask(spd_node->remote_subnet), spd_node->dstport, get_ip(spd_node->remote_subnet));
    len += dst_len; p += dst_len;


    msg->sadb_msg_len = len/8;

    TRACE("print_sadb_msg pfkeyv2_addpolicy");
    print_sadb_msg(msg, len);
    Write(s, buf, len);
    close(s);
    


    // read the policy index asigned by the kernel
    char tmp_local_subnet[MAX_IP];
    char tmp_remote_subnet[MAX_IP];
    char *tmp_tunnel_local = "";
    char *tmp_tunnel_remote = "";
    int tmp_protocol_parameters;
    int tmp_action;
    int tmp_policy_dir;
    int tmp_inner_protocol;
    int tmp_srcport;
    int tmp_dstport;
    int tmp_ipsec_mode;
    int tmp_index;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    int type = SADB_SATYPE_UNSPEC;
    struct sadb_msg tmp_msg;
    bzero(&tmp_msg, sizeof (tmp_msg));
    tmp_msg.sadb_msg_version = PF_KEY_V2;
    tmp_msg.sadb_msg_type = SADB_X_SPDDUMP;
	if (spd_node->protocol_parameters == IPPROTO_ESP)
    	tmp_msg.sadb_msg_satype = SADB_SATYPE_ESP;
    tmp_msg.sadb_msg_len = sizeof (tmp_msg) / 8;
    tmp_msg.sadb_msg_pid = getpid();
    Write(s, &tmp_msg, sizeof (tmp_msg));

       
    int goteof = 0;
    while (goteof == 0) {
        int     msglen;
        struct sadb_msg *msgp;
        msglen = Read(s, &buf2, sizeof (buf2));
        msgp = (struct sadb_msg *) &buf2;

        msglen -= sizeof(struct sadb_msg);
        struct sadb_ext *ext;
        ext = (struct sadb_ext *)(msgp + 1);

        while (msglen > 0) {
        
            struct sadb_x_policy *policy;
            struct sockaddr *sa;
            struct sadb_address *addr;

            switch (ext->sadb_ext_type) {
                case SADB_X_EXT_POLICY: 
                    policy = (struct sadb_x_policy *)ext;
                    tmp_index = policy->sadb_x_policy_id;
                    tmp_action = policy->sadb_x_policy_type;
                    tmp_policy_dir = policy->sadb_x_policy_dir;

                    struct sadb_x_ipsecrequest *xisr;
                    size_t off = sizeof(*policy);
                    while (off < PFKEY_EXTLEN(policy)) {    
                        int offset;
                        xisr = (void *)((caddr_t)(void *)policy + off);
                        tmp_ipsec_mode = xisr->sadb_x_ipsecrequest_mode;
                        tmp_protocol_parameters = xisr->sadb_x_ipsecrequest_proto;
                        off += xisr->sadb_x_ipsecrequest_len;
                    }    
                    break;
                case SADB_EXT_ADDRESS_SRC:
                case SADB_EXT_ADDRESS_DST:
                    addr = (struct sadb_address *)ext;
                    sa = (struct sockaddr *)(addr + 1);
                    if (addr->sadb_address_exttype == SADB_EXT_ADDRESS_SRC)
                        strcpy(tmp_local_subnet,sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
                    else 
                        strcpy(tmp_remote_subnet,sock_ntop(sa, addr->sadb_address_len * 8 - sizeof(*addr)));
                    break;
            }
            msglen -= ext->sadb_ext_len << 3;
            ext = (struct sadb_ext*) ((char *)ext + (ext->sadb_ext_len << 3));
        }

        if ((strcmp(get_ip(spd_node->local_subnet),tmp_local_subnet) == 0) &&
            (strcmp(get_ip(spd_node->remote_subnet),tmp_remote_subnet) == 0) &&
            (spd_node->policy_dir == tmp_policy_dir) 
            ) {
                spd_node->index = tmp_index;
                goteof = 1;
                break;
        } 

        if (msgp->sadb_msg_seq == 0)
             goteof = 1;
    }  
    close(s);  
    TRACE("print_sadb_msg pfkeyv2_addpolicy end"); 
    return SR_ERR_OK;

}

int pf_delpolicy(spd_entry_node *spd_node) {

    char buf[PFKEY_BUFFER_SIZE], *p;
    struct sadb_msg *msg;
    struct sadb_x_policy *policyext;
    int s, len,i;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    bzero(&buf, sizeof(buf));

    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version =  PF_KEY_V2;
    msg->sadb_msg_type = SADB_X_SPDDELETE;
	if (spd_node->protocol_parameters == IPPROTO_ESP)
    	msg->sadb_msg_satype = SADB_SATYPE_ESP;
    //msg->sadb_msg_satype = spd_node->protocol_parameters;
    len = sizeof(*msg);
    p += sizeof(*msg);

    policyext = (struct sadb_x_policy *) p;
    policyext->sadb_x_policy_len = sizeof(struct sadb_x_policy)/8;
    policyext->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policyext->sadb_x_policy_type = spd_node->action;
    policyext->sadb_x_policy_dir = spd_node->policy_dir;
    len += policyext->sadb_x_policy_len *8;
    p += policyext->sadb_x_policy_len *8;

    int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, spd_node->inner_protocol, get_mask(spd_node->local_subnet), spd_node->srcport, get_ip(spd_node->local_subnet));
    p += src_len; len += src_len;

    int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, spd_node->inner_protocol, get_mask(spd_node->remote_subnet), spd_node->dstport, get_ip(spd_node->remote_subnet));
    len += dst_len; p += dst_len;

    msg->sadb_msg_len = len/8;

    TRACE("print_sadb_msg pfkeyv2_delpolicy");
    print_sadb_msg(msg, len);
    TRACE("end print_sadb_msg pfkeyv2_delpolicy");
    Write(s, buf, len);
    close(s);

    return SR_ERR_OK;

}


// TODO Parser the structure that has been received from what it has been defined by UMU
int pf_addsad(sad_entry_node *sad_node) {
    int s;
    char buf[4096], *p;
    struct sadb_msg *msg;
    struct sadb_sa *saext;
    struct sadb_x_sa2 *sa2;
    struct sadb_key *keyext;
    struct sadb_address *addrext;
    int len;
    int mypid;
    int rc = SR_ERR_OK;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    mypid = getpid();
    //http://www.cs.fsu.edu/~baker/devices/lxr/source/2.6.31.13/linux/net/key/af_key.c 
    // Build and write SADB_ADD request 
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version = PF_KEY_V2;
    msg->sadb_msg_type = SADB_ADD;
	if (sad_node->protocol_parameters == IPPROTO_ESP)
    	msg->sadb_msg_satype = SADB_SATYPE_ESP;
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);

    saext = (struct sadb_sa *) p;
    saext->sadb_sa_len = sizeof(struct sadb_sa)/ 8;
    saext->sadb_sa_exttype = SADB_EXT_SA;
    saext->sadb_sa_spi = htonl(sad_node->spi);
    saext->sadb_sa_replay = sad_node->anti_replay_window;
    saext->sadb_sa_state = SADB_SASTATE_MATURE;
    saext->sadb_sa_encrypt = sad_node->encryption_alg;
    saext->sadb_sa_auth = sad_node->integrity_alg;
    saext->sadb_sa_flags = 0;
    len += saext->sadb_sa_len * 8;
    p += saext->sadb_sa_len * 8;

    sa2 = (struct sadb_x_sa2*) p;
    sa2->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
    sa2->sadb_x_sa2_len = sizeof(struct sadb_spirange)/8;
    sa2->sadb_x_sa2_mode = sad_node->ipsec_mode;
    sa2->sadb_x_sa2_reqid = sad_node->req_id;
    //sa2->sadb_x_sa2_sequence = sad_node->seq_number;
    len += sa2->sadb_x_sa2_len * 8;
    p += sa2->sadb_x_sa2_len * 8;
    
    struct sadb_lifetime *lifetime;
    
    lifetime = (struct sadb_lifetime *)p;
    lifetime->sadb_lifetime_len = sizeof(struct sadb_lifetime)/sizeof(uint64_t);
    lifetime->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
    lifetime->sadb_lifetime_allocations =  sad_node->lft_packets_hard;
    lifetime->sadb_lifetime_bytes = sad_node->lft_bytes_hard;
    lifetime->sadb_lifetime_usetime = sad_node->lft_idle_hard;
    lifetime->sadb_lifetime_addtime = sad_node->lft_time_hard;
    len += lifetime->sadb_lifetime_len * 8;
    p += lifetime->sadb_lifetime_len * 8;
    
    lifetime = (struct sadb_lifetime *) p;
    lifetime->sadb_lifetime_len = sizeof(struct sadb_lifetime)/sizeof(uint64_t);
    lifetime->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
    lifetime->sadb_lifetime_allocations =  sad_node->lft_packets_soft;
    lifetime->sadb_lifetime_bytes = sad_node->lft_bytes_soft;
    lifetime->sadb_lifetime_usetime = sad_node->lft_idle_soft;
    lifetime->sadb_lifetime_addtime = sad_node->lft_time_soft;
    len += lifetime->sadb_lifetime_len * 8;
    p += lifetime->sadb_lifetime_len * 8;


    if(sad_node->ipsec_mode == IPSEC_MODE_TUNNEL){
    
        int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->inner_protocol, 32, sad_node->srcport, sad_node->tunnel_local);
        p += src_len; len += src_len;
        int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->inner_protocol, 32, sad_node->dstport, sad_node->tunnel_remote);
        len += dst_len; p += dst_len;
    
    } else {

        int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->inner_protocol, get_mask(sad_node->local_subnet), sad_node->srcport, get_ip(sad_node->local_subnet));
        p += src_len; len += src_len;    
        int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->inner_protocol, get_mask(sad_node->remote_subnet), sad_node->dstport, get_ip(sad_node->remote_subnet));
        len += dst_len; p += dst_len;
    }

    // TODO support more algorithms
    if(sad_node->encryption_alg != SADB_EALG_NONE){
            keyext = (struct sadb_key *) p;
            keyext->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
            keyext->sadb_key_reserved = 0;
            // INFO("-----------KeyExt size %d",sizeof(*keyext)); 
            if(sad_node->encryption_alg == SADB_EALG_DESCBC){
                DBG("selected SADB_EALG_DESCBC");
                    keyext->sadb_key_len = (sizeof(*keyext) + (EALG_DESCBC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = EALG_DESCBC_KEY_BITS;
            } // SADB_X_EALG_AESCBC
            else if (sad_node->encryption_alg==SADB_X_EALG_AESCBC){
                DBG("selected SADB_X_EALG_AESCBC");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_KEY_BITS;   
            } else if (sad_node->encryption_alg==SADB_EALG_3DESCBC) {
                DBG("selected SADB_EALG_3DESCBC");
                keyext->sadb_key_len = (sizeof(*keyext) + (EALG_3DESCBC_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EALG_3DESCBC_KEY_BITS;
            } else if (sad_node->encryption_alg==SADB_X_EALG_CASTCBC) {
                DBG("selected SADB_X_EALG_CASTCBC");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_CASTCBC_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_CASTCBC_KEY_BITS;
            } else if (sad_node->encryption_alg==SADB_X_EALG_AESCTR) {
                DBG("selected SADB_X_EALG_AESCTR");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AESCTR_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AESCTR_KEY_BITS;
            } else if (sad_node -> encryption_alg==SADB_X_EALG_AES_CCM_ICV8) {
                DBG("selected SADB_X_EALG_AES_CCM_ICV8");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_CCM_ICV8_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_CCM_ICV8_KEY_BITS;
            } else if (sad_node -> encryption_alg==SADB_X_EALG_AES_CCM_ICV12) {
                DBG("selected SADB_X_EALG_AES_CCM_ICV12");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_CCM_ICV12_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_CCM_ICV12_KEY_BITS;
            } else if (sad_node -> encryption_alg==SADB_X_EALG_AES_CCM_ICV16) {
                DBG("selected SADB_X_EALG_AES_CCM_ICV16");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_CCM_ICV16_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_CCM_ICV16_KEY_BITS;
            } else if (sad_node -> encryption_alg==SADB_X_EALG_AES_GCM_ICV8) {
                DBG("selected SADB_X_EALG_AES_GCM_ICV8");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_GCM_ICV8_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_GCM_ICV8_KEY_BITS;
            } else if (sad_node -> encryption_alg==SADB_X_EALG_AES_GCM_ICV12) {
                DBG("selected SADB_X_EALG_AES_GCM_ICV12");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_GCM_ICV12_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_GCM_ICV12_KEY_BITS;
            } else if (sad_node -> encryption_alg==SADB_X_EALG_AES_GCM_ICV16) {
                DBG("selected SADB_X_EALG_AES_GCM_ICV16");
                keyext->sadb_key_len = (sizeof(*keyext) + (EAL_AES_GCM_ICV16_KEY_BITS/8) + 7) / 8;
                keyext->sadb_key_bits = EAL_AES_GCM_ICV16_KEY_BITS;
            }
            // INFO("-----------Key length %d",keyext->sadb_key_len); 
            memcpy(keyext + 1, sad_node->encryption_key, strlen(sad_node->encryption_key));
            len += keyext->sadb_key_len * 8;
            p += keyext->sadb_key_len * 8;
    }

    // TODO support more algorithms
    if(sad_node->integrity_alg != SADB_AALG_NONE){
        keyext = (struct sadb_key *) p;
            keyext->sadb_key_exttype = SADB_EXT_KEY_AUTH;
            keyext->sadb_key_reserved = 0;
            if(sad_node->integrity_alg == AALG_MD5HMAC_KEY_BITS){
                    keyext->sadb_key_len = (sizeof(*keyext) + (AALG_MD5HMAC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = AALG_MD5HMAC_KEY_BITS;
            }
            else{
                    keyext->sadb_key_len = (sizeof(*keyext) + (AALG_SHA1HMAC_KEY_BITS/8) + 7) / 8;
                    keyext->sadb_key_bits = AALG_SHA1HMAC_KEY_BITS;
            }
            memcpy(keyext + 1, sad_node->integrity_key,  strlen(sad_node->integrity_key));
            len += keyext->sadb_key_len * 8;
            p += keyext->sadb_key_len * 8;
    }
    msg->sadb_msg_len = len / 8;
    TRACE("print_sadb_msg pfkeyv2_addsad:");
    print_sadb_msg(msg, len);
    TRACE("end print_sadb_msg pfkeyv2_addsad:");
    Write(s, buf, len);
    close(s);
    return SR_ERR_OK;
}


int pf_delsad(sad_entry_node *sad_node) {
    struct sadb_msg *msg;
    struct sadb_x_policy *policyext;
    int s, len, spi;
    int rc = SR_ERR_OK;
    char buf[4096], *p;
    struct sadb_sa *saext;
    struct sadb_x_sa2 *sa2;
    struct sadb_key *keyext;
    struct sadb_address *addrext;
    int mypid;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    mypid = getpid();

    // Build and write SADB_ADD request 
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version = PF_KEY_V2;
    msg->sadb_msg_type = SADB_DELETE;
    msg->sadb_msg_satype = proto2satype(sad_node->protocol_parameters);
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);

    saext = (struct sadb_sa *) p;
    saext->sadb_sa_len = sizeof(struct sadb_sa)/ 8;
    saext->sadb_sa_exttype = SADB_EXT_SA;
    saext->sadb_sa_spi = htonl(sad_node->spi);
    len += saext->sadb_sa_len * 8;
    p += saext->sadb_sa_len * 8;


    int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->inner_protocol, get_mask(sad_node->local_subnet), sad_node->srcport, get_ip(sad_node->local_subnet));
    p += src_len; len += src_len;
    int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->inner_protocol, get_mask(sad_node->remote_subnet), sad_node->dstport, get_ip(sad_node->remote_subnet));
    len += dst_len; p += dst_len;


    msg->sadb_msg_len = len / 8;
    TRACE("print_sadb_msg pfkeyv2_delsad:");
    print_sadb_msg(msg, len);
    TRACE("end print_sadb_msg pfkeyv2_delsad:");
    Write(s, buf, len);
    close(s);

    return SR_ERR_OK;
}


int pf_getsad(sad_entry_node *sad_node, sad_entry_node *out_node) {
    struct sadb_msg *msg;
    struct sadb_x_policy *policyext;
    int s, len, spi;
    int rc = SR_ERR_OK;
    char buf[4096], *p;
    struct sadb_sa *saext;
    // struct sadb_key *keyext;
    // struct sadb_address *addrext;
    int mypid;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    mypid = getpid();

    // Build and write SADB_ADD request 
    bzero(&buf, sizeof(buf));
    p = buf;
    msg = (struct sadb_msg *) p;
    msg->sadb_msg_version = PF_KEY_V2;
    msg->sadb_msg_type = SADB_GET;
	if (sad_node->protocol_parameters == IPPROTO_ESP)
    	msg->sadb_msg_satype = SADB_SATYPE_ESP;
    msg->sadb_msg_pid = getpid();
    len = sizeof(*msg);
    p += sizeof(*msg);

    saext = (struct sadb_sa *) p;
    saext->sadb_sa_len = sizeof(struct sadb_sa)/ 8;
    saext->sadb_sa_exttype = SADB_EXT_SA;
    saext->sadb_sa_spi = htonl(sad_node->spi);
    len += saext->sadb_sa_len * 8;
    p += saext->sadb_sa_len * 8;

    if(sad_node->ipsec_mode == IPSEC_MODE_TUNNEL){
        int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->inner_protocol, 32, sad_node->srcport, sad_node->tunnel_local);
        p += src_len; len += src_len;
        int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->inner_protocol, 32, sad_node->dstport, sad_node->tunnel_remote);
        len += dst_len; p += dst_len;
    } else {
        int src_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_SRC, sad_node->inner_protocol, get_mask(sad_node->local_subnet), sad_node->srcport, get_ip(sad_node->local_subnet));
        p += src_len; len += src_len;    
        int dst_len = pf_setsadbaddr(p,SADB_EXT_ADDRESS_DST, sad_node->inner_protocol, get_mask(sad_node->remote_subnet), sad_node->dstport, get_ip(sad_node->remote_subnet));
        len += dst_len; p += dst_len;
    }


    msg->sadb_msg_len = len / 8;
    print_sadb_msg(msg, len);
   
    Write(s, buf, len);
     // Read and print SADB_DUMP replies until done 
    int msglen;
    struct sadb_ext *ext;
    struct sadb_msg *msgp;
    msglen = Read(s, &buf, sizeof (buf));
    msgp = (struct sadb_msg *) &buf;
    close(s);

    if (msglen != msgp->sadb_msg_len * 8) {
        ERR("SADB Message length (%d) doesn't match msglen (%d)",
        msgp->sadb_msg_len * 8, msglen);
        return SR_ERR_OPERATION_FAILED;
    }
    if (msgp->sadb_msg_version != PF_KEY_V2) {
        ERR("SADB Message version not PF_KEY_V2");
        return SR_ERR_OPERATION_FAILED;
    }
    if (msgp->sadb_msg_errno != 0) {
        ERR("Unknown errno %s", strerror(msgp->sadb_msg_errno));
    }
    if (msglen == sizeof(struct sadb_msg)) {
        return SR_ERR_OPERATION_FAILED; // no extensions 
    }
    msglen -= sizeof(struct sadb_msg);
    ext = (struct sadb_ext *)(msgp + 1);
    int prefixLenDst, prefixLenSrc;
    char ipDst[MAX_IP], ipSrc[MAX_IP];
    int mode;
    int reqid;
    // TODO extract more information
    // for the moment, in first demo we can check only this values.
    while (msglen > 0) {
        switch (ext->sadb_ext_type) {
            case SADB_EXT_KEY_ENCRYPT:{
                TRACE("Parsing ENC KEY");
                struct  sadb_key *keyext = (struct sadb_key *) ext;
                // out_node->encryption_key = malloc(keyext->sadb_key_bits / 8);
                memcpy(out_node->encryption_key, (char *) (keyext + 1), keyext->sadb_key_bits / 8);
                break;
            }
            case SADB_EXT_KEY_AUTH: {
                TRACE("Parsing INT KEY");
                struct  sadb_key *keyext = (struct sadb_key *) ext;
                // out_node->integrity_key = malloc(keyext->sadb_key_bits / 8);
                memcpy(out_node->integrity_key, (char *) (keyext + 1), keyext->sadb_key_bits / 8);
                break;
            }
            case SADB_EXT_SA: {
                struct sadb_sa *sa;
                sa = (struct sadb_sa *)ext;
                TRACE("Parsing SPI %i",ntohl(sa->sadb_sa_spi));
                out_node->spi = ntohl(sa->sadb_sa_spi);
                break;
            }
            case SADB_X_EXT_SA2: {
                struct sadb_x_sa2 *sa2; 
                sa2 = (struct sadb_x_sa2 *) ext;
                mode = sa2->sadb_x_sa2_mode;
                reqid = sa2->sadb_x_sa2_reqid;
                break;
            }
            case SADB_EXT_ADDRESS_SRC: {
                struct sadb_address *addrext = (struct sadb_address *) ext;
                int addr_len = (addrext->sadb_address_len * 8) - sizeof(struct sadb_address);
                struct sockaddr_in *addr = (struct sockaddr_in *) (addrext + 1);
                strcpy(ipSrc,inet_ntoa(addr->sin_addr));
                // int port = ntohs(addr->sin_port);
                // int protocol = addrext->sadb_address_proto;
                prefixLenSrc = addrext->sadb_address_prefixlen;
                break;
            }
            case SADB_EXT_ADDRESS_DST: {
                struct sadb_address *addrext = (struct sadb_address *) ext;
                int addr_len = (addrext->sadb_address_len * 8) - sizeof(struct sadb_address);
                struct sockaddr_in *addr = (struct sockaddr_in *) (addrext + 1);
                strcpy(ipDst,inet_ntoa(addr->sin_addr));
                // int port = ntohs(addr->sin_port);
                // int protocol = addrext->sadb_address_proto;
                prefixLenDst = addrext->sadb_address_prefixlen;
                break;
            }
            
            //default: DBG("ext type: %i", ext->sadb_ext_type);
        }
        msglen -= ext->sadb_ext_len << 3;
        ext = (struct sadb_ext*) ((char *)ext + (ext->sadb_ext_len << 3));
    }
    out_node->ipsec_mode = mode;
    out_node->req_id = reqid;
    if (mode == IPSEC_MODE_TUNNEL) {
        strcpy(out_node->tunnel_local,ipSrc);
        strcpy(out_node->tunnel_remote,ipDst);
    } else {
        sprintf(out_node->local_subnet,"%s/%d",ipSrc,prefixLenSrc);
        sprintf(out_node->remote_subnet,"%s/%d",ipDst,prefixLenDst);
    }
    return SR_ERR_OK;
}


// Review and merge with code in utils.c
char * pf_get_alg_enum_name(struct sadb_alg * alg, struct sadb_supported *sup) {

    char name[100];

    if ("Null" ==  get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype)){
        return NULL;
    } 

    strcpy(name,get_sadb_alg_type(alg->sadb_alg_id, sup->sadb_supported_exttype));

    if (0 == strcmp(name,"HMAC-MD5")) {
        return "hmac-md5-96";
    } else if (0 == strcmp(name,"HMAC-SHA-1")) {
        return "hmac-sha1-96";
    } else if (0 == strcmp(name,"DES-CBC")) {
        return "des";
    } else if (0 == strcmp(name,"3DES-CBC")) {
        return "3des";
    } else if (0 == strcmp(name,"Blowfish-CBC")) {
        return "blowfish";
    } else {
        TRACE("pf_get_alg_enum_name unknown : %s]", name);
        return NULL;
    }
    
}

int pf_dump_sads(sad_entry_node *sad_node) {
    struct sadb_ext *ext;
    int i = 0;
    int s;
    char buf[4096];
    struct sadb_msg msg;
    int goteof;
    int rc = 0;   
    int type = SADB_SATYPE_UNSPEC;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    
      // Build and write SADB_DUMP request 
    bzero(&msg, sizeof (msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof (msg) / 8;
    msg.sadb_msg_pid = getpid();
    //print_sadb_msg (&msg, sizeof (msg));
    Write(s, &msg, sizeof (msg));

     // Read and print SADB_DUMP replies until done 
    goteof = 0;
    while (goteof == 0) {
        int     msglen;
        struct sadb_msg *msgp;

        msglen = Read(s, &buf, sizeof (buf));
        msgp = (struct sadb_msg *) &buf;
        

        if (msglen != msgp->sadb_msg_len * 8) {
            ERR("SADB Message length (%d) doesn't match msglen (%d)",
            msgp->sadb_msg_len * 8, msglen);
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_version != PF_KEY_V2) {
            ERR("SADB Message version not PF_KEY_V2");
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_errno != 0)
            ERR("Unknown errno %s", strerror(msgp->sadb_msg_errno));
        if (msglen == sizeof(struct sadb_msg))
            return SR_ERR_OPERATION_FAILED; // no extensions 
        msglen -= sizeof(struct sadb_msg);
        ext = (struct sadb_ext *)(msgp + 1);

        while (msglen > 0) {
        
            struct sadb_sa *sa;
            struct sadb_lifetime *life;;

            switch (ext->sadb_ext_type) {
                case SADB_EXT_SA: 
                    sa = (struct sadb_sa *)ext;
                    if (ntohl(sa->sadb_sa_spi) == sad_node->spi) {
                        DBG("SA %i found",sad_node->spi);
                        i = 1;
                    }  
                    break;
                    
                case SADB_EXT_LIFETIME_CURRENT:
                    life = (struct sadb_lifetime *)ext;
                    sad_node->lft_packets_current = life->sadb_lifetime_allocations;
                    sad_node->lft_bytes_current = life->sadb_lifetime_bytes;
                    time_t a = life->sadb_lifetime_addtime;
                    sad_node->lft_time_current = (uint64_t)a;
                    if (life->sadb_lifetime_usetime == 0) {
                        //DBG("never used");
                        sad_node->lft_idle_current = 0;
                    } else {
                        time_t u = life->sadb_lifetime_usetime;
                        sad_node->lft_idle_current = (uint64_t)u;
                    }
                    break;
                //default: DBG("ext type: %i", ext->sadb_ext_type);
            }
            msglen -= ext->sadb_ext_len << 3;
            ext = (struct sadb_ext*) ((char *)ext + (ext->sadb_ext_len << 3));
        }

        // if (i == 1) return SR_ERR_OK;

        if (msgp->sadb_msg_seq == 0)
             goteof = 1;
    }
    close(s);
    return SR_ERR_NOT_FOUND;
}



int pf_get_sad_lifetime_current_by_spi(sad_entry_node *node)
{

    struct sadb_ext *ext;
    int i = 0;
    int s;
    char buf[4096];
    struct sadb_msg msg;
    int goteof;
    int rc = 0;   
    int type = SADB_SATYPE_UNSPEC;

    s = Socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    
      // Build and write SADB_DUMP request 
    bzero(&msg, sizeof (msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof (msg) / 8;
    msg.sadb_msg_pid = getpid();
    //print_sadb_msg (&msg, sizeof (msg));
    Write(s, &msg, sizeof (msg));

     // Read and print SADB_DUMP replies until done 
    goteof = 0;
    while (goteof == 0) {
        int     msglen;
        struct sadb_msg *msgp;

        msglen = Read(s, &buf, sizeof (buf));
        msgp = (struct sadb_msg *) &buf;
        

        if (msglen != msgp->sadb_msg_len * 8) {
            ERR("SADB Message length (%d) doesn't match msglen (%d)",
            msgp->sadb_msg_len * 8, msglen);
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_version != PF_KEY_V2) {
            ERR("SADB Message version not PF_KEY_V2");
            return SR_ERR_OPERATION_FAILED;
        }
        if (msgp->sadb_msg_errno != 0)
            ERR("Unknown errno %s", strerror(msgp->sadb_msg_errno));
        if (msglen == sizeof(struct sadb_msg))
            return SR_ERR_OPERATION_FAILED; // no extensions 
        msglen -= sizeof(struct sadb_msg);
        ext = (struct sadb_ext *)(msgp + 1);

        while (msglen > 0) {
        
            struct sadb_sa *sa;
            struct sadb_lifetime *life;;

            switch (ext->sadb_ext_type) {
                case SADB_EXT_SA: 
                    sa = (struct sadb_sa *)ext;
                    if (ntohl(sa->sadb_sa_spi) == node->spi) {
                        DBG("SA %i found",node->spi);
                        i = 1;
                    }  
                    break;
                case SADB_EXT_LIFETIME_CURRENT:
                    life = (struct sadb_lifetime *)ext;
                    node->lft_packets_current = life->sadb_lifetime_allocations;
                    node->lft_bytes_current = life->sadb_lifetime_bytes;
                    time_t a = life->sadb_lifetime_addtime;
                    node->lft_time_current = (uint64_t)a;
                    if (life->sadb_lifetime_usetime == 0) {
                        //DBG("never used");
                        node->lft_idle_current = 0;
                    } else {
                        time_t u = life->sadb_lifetime_usetime;
                        node->lft_idle_current = (uint64_t)u;
                    }
                    break;
                //default: DBG("ext type: %i", ext->sadb_ext_type);
            }
            msglen -= ext->sadb_ext_len << 3;
            ext = (struct sadb_ext*) ((char *)ext + (ext->sadb_ext_len << 3));
        }

        if (i == 1) return SR_ERR_OK;

        if (msgp->sadb_msg_seq == 0)
             goteof = 1;
    }
    close(s);
    return SR_ERR_NOT_FOUND;

}