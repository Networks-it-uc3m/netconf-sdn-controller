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


#ifndef __SPD_ENTRY
#define __SPD_ENTRY

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "constants.h"

// typedef struct host_t host_t;
typedef struct spd_entry_node {
	char *name;
	int index;
	unsigned short policy_dir;
	unsigned int req_id;
	char *local_subnet;
	char *remote_subnet;
	char *tunnel_local;
	char *tunnel_remote;
	unsigned int inner_protocol;
	unsigned int srcport, dstport;
	unsigned short action;
	bool ext_seq_num;
	bool seq_overflow;
	unsigned short ipsec_mode;
	unsigned short protocol_parameters;
	unsigned int integrity_alg;
	unsigned int encryption_alg;
	unsigned long long int anti_replay_window;
	bool pfp_flag;
	bool stateful_frag_check;
	bool bypass_dscp;
	bool ecn;
	bool tfc_pad;
	unsigned short df_bit;

	struct spd_entry_node *next;

} spd_entry_node;

/// @brief creates an empty spd_entry_node with all the inputs intitilized
/// @return an empty sad_entry_node
spd_entry_node* create_spd_node();

#endif