/*
 * Copyright (C) 2006-2014 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup host host
 * @{ @ingroup networking
 */

#ifndef HOST_H_
#define HOST_H_


typedef enum host_diff_t host_diff_t;
typedef struct host_t host_t;

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

// https://github.com/strongswan/strongswan/blob/master/src/libstrongswan/utils/chunk.h
typedef struct chunk_t chunk_t;

/**
 * General purpose pointer/length abstraction.
 */
struct chunk_t {
	/** Pointer to start of data */
	u_char *ptr;
	/** Length of data in bytes */
	size_t len;
};


// https://fossies.org/dox/tinc-1.0.36/net_8h_source.html
typedef struct sockaddr_unknown {
     uint16_t family;
     uint16_t pad1;
     uint32_t pad2;
     char *address;
     char *port;
};

typedef union sockaddr_t {
     struct sockaddr sa;
     struct sockaddr_in in;
     struct sockaddr_in6 in6;
     struct sockaddr_unknown unknown;
 #ifdef HAVE_STRUCT_SOCKADDR_STORAGE
     struct sockaddr_storage storage;
 #endif
} sockaddr_t;


/**
 * Represents a Host
 *
 * Host object, identifies a address:port pair and defines some
 * useful functions on it.
 */
struct host_t {

	/**
	 * Build a clone of this host object.
	 *
	 * @return		cloned host
	 */
	host_t *(*clone) (host_t *this);

	/**
	 * Get a pointer to the internal sockaddr struct.
	 *
	 * This is used for sending and receiving via sockets.
	 *
	 * @return		pointer to the internal sockaddr structure
	 */
	sockaddr_t  *(*get_sockaddr) (host_t *this);

	/**
	 * Get the length of the sockaddr struct.
	 *
	 * Depending on the family, the length of the sockaddr struct
	 * is different. Use this function to get the length of the sockaddr
	 * struct returned by get_sock_addr.
	 *
	 * This is used for sending and receiving via sockets.
	 *
	 * @return		length of the sockaddr struct
	 */
	socklen_t *(*get_sockaddr_len) (host_t *this);

	/**
	 * Gets the family of the address
	 *
	 * @return		family
	 */
	int (*get_family) (host_t *this);

	/**
	 * Checks if the ip address of host is set to default route.
	 *
	 * @return		TRUE if host is 0.0.0.0 or 0::0, FALSE otherwise
	 */
	bool (*is_anyaddr) (host_t *this);

	/**
	 * Get the address of this host as chunk_t
	 *
	 * Returned chunk points to internal data.
	 *
	 * @return		address blob
	 */
	chunk_t (*get_address) (host_t *this);

	/**
	 * Get the port of this host
	 *
	 * @return		port number
	 */
	uint16_t (*get_port) (host_t *this);

	/**
	 * Set the port of this host
	 *
	 * @param port	port number
	 */
	void (*set_port) (host_t *this, uint16_t port);

	/**
	 * Compare the ips of two hosts hosts.
	 *
	 * @param other	the other to compare
	 * @return		TRUE if addresses are equal.
	 */
	bool (*ip_equals) (host_t *this, host_t *other);

	/**
	 * Compare two hosts, with port.
	 *
	 * @param other	the other to compare
	 * @return		TRUE if addresses and ports are equal.
	 */
	bool (*equals) (host_t *this, host_t *other);

	/**
	 * Destroy this host object.
	 */
	void (*destroy) (host_t *this);
};

#endif /** HOST_H_ @}*/