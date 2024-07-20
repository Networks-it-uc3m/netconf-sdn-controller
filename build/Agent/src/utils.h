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

#include <stdint.h>


#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
// #include <signal.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <crypt.h>


// #include "pfkeyv2_utils.h"
#include "log.h"
#include "constants.h"
#include "sad_entry.h"
#ifdef TRUSTED_APP
#endif 


char * get_ip(char * ip_mask);
int get_mask(char * ip_mask);
void set_verbose(int setting);
int v_printf(const char * restrict format, ...);
const char * get_sadb_msg_type(int type);
const char * get_sadb_satype(int type);
const char * get_sadb_alg_type(int alg, int authenc);
int Socket(int family, int type, int protocol);
void Write(int fd, void *ptr, size_t nbytes);
ssize_t Read(int fd, void *ptr, size_t nbytes);
char * sock_ntop(const struct sockaddr *sa, socklen_t salen);
const char * get_sa_state(int state);
const char * get_encrypt_str(int alg);
const char * get_auth_str(int alg);
const char * get_auth_alg(int alg);
const char * get_encrypt_alg(int alg);
int getAuthAlg(char* alg);
int getEncryptAlg(char* alg);
unsigned char* hexstr_to_char(char* hexstr);
int checkIKE_connection();
void remove_colon(char* out, char* str) ;
int compare_sad_entries(sad_entry_node *i, sad_entry_node *j);
char* stringToBytes(char* str);

// Mngmt of local sad-entries

/// @brief Get sad_entry from the local database 
/// @param main_sad_entry local sad_entry database
/// @param sad_name sad_entry name identifier
/// @return local sad_enrtry (if NULL it does not exists)
sad_entry_node *get_sad_node(sad_entry_node** main_sad_entry, char *sad_name);
/// @brief Returns a sad_entry if the SPI exists in the local_database
/// @param main_sad_entry local sad_entry database
/// @param spi SPI of the entry to be found
/// @return local sad_enrtry (if NULL it does not exists)
sad_entry_node *get_sad_node_by_spi(sad_entry_node** main_sad_entry, unsigned long int spi);
/// @brief Deletes a sad_entry (identified by their name) from the local_database
/// @param main_sad_entry Local sad_entry database
/// @param sad_name Name of the 
/// @return 
int del_sad_node(sad_entry_node** main_sad_entry, char *sad_name);
/// @brief Add a sad_entry into the local database 
/// @param main_sad_entry local sad_entry database
/// @param sad_name new sad_entry
/// @return 
int add_sad_node(sad_entry_node** main_sad_entry, sad_entry_node* new_sad);


/// @brief Prints current values of the local sad_entry database
/// @param main_sad_entry local sad_entry database
void show_sad_list(sad_entry_node* main_sad_entry);


// TODO: Do the same thing but with the spd_entries.
// Mngmt of local spd-entries
// spd_entry_node *get_spd_node(spd_entry_node* main_spd_entry, char *spd_name);
// spd_entry_node *get_spd_node_by_spi(spd_entry_node* main_spd_entry, unsigned long int spi);
// int del_spd_node(spd_entry_node* main_spd_entry, unsigned long int spi);
// int add_spd_node(spd_entry_node* main_spd_entry, spd_entry_node* new_spd);

