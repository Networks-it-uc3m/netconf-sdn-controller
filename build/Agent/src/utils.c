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

#include "utils.h"
#include <inttypes.h>

char * get_ip(char * ip_mask) {

	const char d[2] = "/";
	char * ip;

    ip = strdup(ip_mask);
    ip = strtok(ip,d);
	// INFO("Calculated IP: %s",ip)
 	return ip;
}

int get_mask(char * ip_mask) {

	const char d[2] = "/";
	/*char address_tmp[30];
    char *ip;
	char *mask = NULL;

	mask = strrchr(ip_mask, '/');
     
 	return atoi(mask);*/
	char * ip;
	char * mask;

    ip = strdup(ip_mask);
    ip = strtok(ip,d);
 	mask = strtok(NULL,d);
 	return atoi(mask);

}

int getAuthAlg(char* alg) {

	if (!strcmp(alg, "hmac-md5-128") || !strcmp(alg, "hmac-md5-96")){
		return SADB_AALG_MD5HMAC;
	}
	/*else if (!strcmp(alg, "des-mac"))
		return SADB_X_AALG_DES;*/
	else if (!strcmp(alg, "hmac-sha1-96") || !strcmp(alg, "hmac-sha1-96") ||
		     !strcmp(alg, "hmac-sha1-160"))
		return SADB_AALG_SHA1HMAC;
	/*else if (!strcmp(alg, "hmac-sha2-256-128"))
		return SADB_X_AALG_SHA2_256;
	else if (!strcmp(alg, "hmac-sha2-384-192"))
		return SADB_X_AALG_SHA2_384;
	else if (!strcmp(alg, "hmac-sha2-512-256"))
		return SADB_X_AALG_SHA2_512;*/
	else 
		return SADB_AALG_NONE;
}

int getEncryptAlg(char* alg) {

	if (!strcmp(alg, "des"))
		return SADB_EALG_DESCBC ;
	else if (!strcmp(alg, "3des"))
		return SADB_EALG_3DESCBC;
	else if (!strcmp(alg,"aes-cbc")) {
		return SADB_X_EALG_AESCBC;
	}
	/*else if (!strcmp(alg, "blowfish-128") || !strcmp(alg, "blowfish-192") ||
		     !strcmp(alg, "blowfish-256") || !strcmp(alg, "blowfish-448") )
		return SADB_X_EALG_BLF;
	else if (!strcmp(alg, "aes-128-cbc") || !strcmp(alg, "aes-192-cbc") ||
		     !strcmp(alg, "aes-256-cbc"))
		return SADB_X_EALG_AES;
	else if (!strcmp(alg, "cast"))
		return SADB_X_EALG_CAST;
	else if (!strcmp(alg, "aes-ctr"))
		return SADB_X_EALG_AESCTR;
	else if (!strcmp(alg, "camellia-128") || !strcmp(alg, "camellia-192") ||
		     !strcmp(alg, "camellia-256") )
		return SADB_EALG_NULL;*/
	else
		return SADB_EALG_NULL;
}

const char * get_encrypt_str(int alg) {

    static char buf[100];
    switch (alg) {
    case SADB_EALG_DESCBC:      return "des";
    case SADB_EALG_3DESCBC:     return "3des";
    case SADB_EALG_NULL:        return "null";
	case SADB_X_EALG_AESCBC:    return "aes-cbc";
#ifdef SADB_X_EALG_CAST128CBC
    case SADB_X_EALG_CAST128CBC:    return "cast";
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
    case SADB_X_EALG_BLOWFISHCBC:   return "blowfish";
#endif
// #ifdef SADB_X_EALG_AESCBC
    
// #endif
    default:                    sprintf(buf, "[Unknown encryption algorithm %d]", alg);
                                return buf;
    }
}

const char *
get_auth_str(int alg) {

    static char buf[100];
    switch (alg) {
    case SADB_AALG_MD5HMAC:     return "hmac-md5-96";
    case SADB_AALG_SHA1HMAC:    return "hmac-sha1-96";
/*#ifdef SADB_X_AALG_MD5
    case SADB_X_AALG_MD5:       return "Keyed MD5";
#endif
#ifdef SADB_X_AALG_SHA
    case SADB_X_AALG_SHA:       return "Keyed SHA-1";
#endif
#ifdef SADB_X_AALG_NULL
    case SADB_X_AALG_NULL:      return "Null";
#endif
#ifdef SADB_X_AALG_SHA2_256
    case SADB_X_AALG_SHA2_256:  return "SHA2-256";
#endif
#ifdef SADB_X_AALG_SHA2_384
    case SADB_X_AALG_SHA2_384:  return "SHA2-384";
#endif
#ifdef SADB_X_AALG_SHA2_512
    case SADB_X_AALG_SHA2_512:  return "SHA2-512";
#endif
*/
    default:                    sprintf(buf, "[Unknown authentication algorithm %d]", alg);
                                return buf;
    }
}

// FROM key/printsadbmsg.c

const char *
get_auth_alg(int alg) {

	static char buf[100];

	switch (alg) {
	case SADB_AALG_NONE:		return "None";
	case SADB_AALG_MD5HMAC:		return "HMAC-MD5";
	case SADB_AALG_SHA1HMAC:	return "HMAC-SHA-1";
#ifdef SADB_X_AALG_MD5
	case SADB_X_AALG_MD5:		return "Keyed MD5";
#endif
#ifdef SADB_X_AALG_SHA
	case SADB_X_AALG_SHA:		return "Keyed SHA-1";
#endif
#ifdef SADB_X_AALG_NULL
	case SADB_X_AALG_NULL:		return "Null";
#endif
#ifdef SADB_X_AALG_SHA2_256
	case SADB_X_AALG_SHA2_256:	return "SHA2-256";
#endif
#ifdef SADB_X_AALG_SHA2_384
	case SADB_X_AALG_SHA2_384:	return "SHA2-384";
#endif
#ifdef SADB_X_AALG_SHA2_512
	case SADB_X_AALG_SHA2_512:	return "SHA2-512";
#endif
	default:					sprintf(buf, "[Unknown authentication algorithm %d]", alg);
								return buf;
	}
}

const char *
get_encrypt_alg(int alg) {

	static char buf[100];

	switch (alg) {
	case SADB_EALG_NONE:		return "None";
	case SADB_EALG_DESCBC:		return "DES-CBC";
	case SADB_EALG_3DESCBC:		return "3DES-CBC";
	case SADB_EALG_NULL:		return "Null";
	case SADB_X_EALG_AESCBC:    return "aes-cbc";
#ifdef SADB_X_EALG_CAST128CBC
	case SADB_X_EALG_CAST128CBC:	return "CAST128-CBC";
#endif
#ifdef SADB_X_EALG_BLOWFISHCBC
	case SADB_X_EALG_BLOWFISHCBC:	return "Blowfish-CBC";
#endif
	default:					sprintf(buf, "[Unknown encryption algorithm %d]", alg);
								return buf;
	}
}

const char *
get_sadb_alg_type(int alg, int authenc) {

	if (authenc == SADB_EXT_SUPPORTED_AUTH) {
		return get_auth_alg(alg);
	} else {
		return get_encrypt_alg(alg);
	}
}

const char *
get_sa_state(int state) {
	static char buf[100];
	switch (state) {
	case SADB_SASTATE_LARVAL:	return "Larval";
	case SADB_SASTATE_MATURE:	return "Mature";
	case SADB_SASTATE_DYING:	return "Dying";
	case SADB_SASTATE_DEAD:		return "Dead";
	default:					sprintf(buf, "[Unknown SA state %d]", state);
								return buf;
	}
}

const char *
get_sadb_msg_type(int type) {
	static char buf[100];
	switch (type) {
	case SADB_RESERVED:	return "Reserved";
	case SADB_GETSPI:	return "Get SPI";
	case SADB_UPDATE:	return "Update";
	case SADB_ADD:		return "Add";
	case SADB_X_SPDADD: return "SADB_X_SPADD";
	case SADB_DELETE:	return "Delete";
	case SADB_GET:		return "Get";
	case SADB_ACQUIRE:	return "Acquire";
	case SADB_REGISTER:	return "Register";
	case SADB_EXPIRE:	return "Expire";
	case SADB_FLUSH:	return "Flush";
	case SADB_DUMP:		return "Dump";
	default:			sprintf(buf, "[Unknown type %d]", type);
						return buf;
	}
}

const char *
get_sadb_satype(int type) {

	static char buf[100];
	switch (type) {
	case SADB_SATYPE_UNSPEC:	return "Unspecified";
	case SADB_SATYPE_AH:		return "IPsec AH";
	case SADB_SATYPE_ESP:		return "IPsec ESP";
	case SADB_SATYPE_RSVP:		return "RSVP";
	case SADB_SATYPE_OSPFV2:	return "OSPFv2";
	case SADB_SATYPE_RIPV2:		return "RIPv2";
	case SADB_SATYPE_MIP:		return "Mobile IP";
	default:					sprintf(buf, "[Unknown satype %d]", type);
								return buf;
	}
}

/* include Socket */
int Socket(int family, int type, int protocol) {

    int n;

    if ( (n = socket(family, type, protocol)) < 0)
        log_error("socket error");
    return(n);
}
/* end Socket */

void
Write(int fd, void *ptr, size_t nbytes) {

    if (write(fd, ptr, nbytes) != nbytes)
       log_error("write error");
}

ssize_t
Read(int fd, void *ptr, size_t nbytes) {

        ssize_t n;

        if ( (n = read(fd, ptr, nbytes)) == -1)
                log_error("read error");
        return(n);
}

char *
sock_ntop(const struct sockaddr *sa, socklen_t salen) {

    char portstr[7];
    static char str[128];		/* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;
		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		if (ntohs(sin->sin_port) != 0) {
			snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin->sin_port));
			strcat(str, portstr);
		}
		return(str);
	}
/* end sock_ntop */
	}
}

// function to remove all occurrences of a character from a string
void remove_all_chars(char* str, char c) {
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}

// function to convert a hex string to a byte array
unsigned char* hexstr_to_char(char* hexstr)
{
	remove_all_chars(hexstr,':');
	size_t len = strlen(hexstr);
    if (len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

void remove_colon(char* out, char* str) {
    int len = strlen(str);
    int j = 0;
    for(int i = 0; i < len; i++) {
        if(str[i] != ':') {
            out[j++] = str[i]; // copy the character to the output buffer if it's not a colon
        }
    }
    out[j] = '\0'; // add the null terminator at the end of the output string
}

char* stringToBytes(char* str) {
    // Calculate the length of the input string
    size_t len = strlen(str);
    
    // Allocate memory for the byte string
    char* bytes = (char*)malloc(len * 2 + 1);  // Each byte is represented by 2 characters in hexadecimal, +1 for null terminator
    
    // Convert each character to byte string
    for (size_t i = 0; i < len; i++) {
        sprintf(bytes + i * 2, "%02X", (unsigned char)str[i]);  // Convert byte value to hexadecimal string
    }
    
    return bytes;
}

int compare_sad_entries(sad_entry_node *i, sad_entry_node *j) {
	// verify enc key
	TRACE("I_ENC_KEY: %s \t J_ENC_KEY: %s",stringToBytes(i->encryption_key),stringToBytes(j->encryption_key));
    if (strncmp(i->encryption_key,j->encryption_key,MAX_KEY) != 0) {
		ERR("Entries ENC KEYS differ");
		return 1;
    }
	// verify int key
	TRACE("I_INT_KEY: %s \t J_INT_KEY: %s",stringToBytes(i->integrity_key),stringToBytes(j->integrity_key));
    if (strncmp(i->integrity_key,j->integrity_key,MAX_KEY) != 0) {
		ERR("Entries AUTH KEYS differ");
		return 1;
    }
	// Check that they have the same SPI
	if (i->spi != j->spi) {
		ERR("Entries SPI differ");
		return 1;
	}
	// Check that they have they are using the same mode
	if (i->ipsec_mode != j->ipsec_mode) {
		ERR("Entries MODE differ");
		return 1;
	}
	// TODO add more verification steps

	// verify iv key for the moment ommit this
    // if (strncmp(i->encryption_iv,j->encryption_iv,MAX_KEY) != 0) {
    //         return 1;
    // }
	return 0;
}



// Mngmt of local sad-entries
sad_entry_node *get_sad_node(sad_entry_node** main_sad_entry, char *sad_name) {
    sad_entry_node *node = *main_sad_entry;
	while (node != NULL) {
		if (!strcmp(node->name, sad_name)) {
			return node;
		} else {
			node = node->next;
		}
	}
	return NULL;
}

sad_entry_node *get_sad_node_by_spi(sad_entry_node** main_sad_entry, unsigned long int spi) {
    sad_entry_node *node = *main_sad_entry;
	while (node != NULL) {
		if (node->spi == spi) {
			return node;
		} else {
			node = node->next;
		}
	}
	return NULL;
}



int del_sad_node(sad_entry_node** main_sad_entry, char *sad_name) {
	// Do we have initialized the sad_node
	if (main_sad_entry == NULL) {
		ERR("There is no SAD_ENTRIES stored");
		return 1;
	}
	// Check that the initial sad_node is not the one we are looking for
	if(strcmp(sad_name,(*main_sad_entry)->name) == 0) {
		// This are some helpers variables
		sad_entry_node *nh = *main_sad_entry;
		// This is redundant, but just to clarify how this should work
		if(nh -> next == NULL) {
			*main_sad_entry = NULL;
		} else {
			*main_sad_entry = (*main_sad_entry)->next;
		}
		free(nh);
	} else {
		sad_entry_node *nc = *main_sad_entry;
		sad_entry_node *np;
		while (strcmp(sad_name,nc->name) != 0) {
				np = nc;
				nc = nc->next;
				if (nc == NULL) {
					ERR("There is no SAD_ENTRIES stored");
					return 1;
				} 
		}
		// Nc is the current node and we want to delete it
		// Np in this case is the previous node
		if (nc == NULL) {
			np->next = NULL;
		} else {
			np->next = nc->next;
		}
		free(nc);
	}
}
int add_sad_node(sad_entry_node** main_sad_entry, sad_entry_node* new_sad) {
    if (*main_sad_entry == NULL) {
		// Do a copy
        *main_sad_entry=new_sad;
        new_sad->next=NULL;
    } else{
        sad_entry_node *node = *main_sad_entry;
        while(node->next != NULL) {
            node=node->next;
		}
        node->next=new_sad;
    }
	return 0;
}

void show_sad_list(sad_entry_node* main_sad_entry) {
    sad_entry_node *node = main_sad_entry;
    INFO("Name -- SPI -- SRC --- DST --- MODE --- ");
    while (node != NULL){
        INFO("%s --- %d --- %s --- %s --- %d --- ", node->name, node->spi, node->local_subnet, node->remote_subnet, node->ipsec_mode);
        node=node->next;
    }
}
