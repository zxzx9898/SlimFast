#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>

#include "chainingHashTable.h"

void link_list_insert (link_list_node_t *link_list, container_unixsocket_mapping_info_t *mapping_info)
{
	/* head insert: two-way linked list*/
    link_list_node_t *node = (link_list_node_t*) malloc (sizeof (link_list_node_t));

    node->mapping_info = mapping_info;
    
    if (link_list->next != NULL)
    {
    	link_list->next->previous = node;
    }
    
    node->previous = link_list;
    node->next = link_list->next;
    link_list->next = node;
}

link_list_node_t *link_list_search_viahashkey (link_list_node_t *link_list, uint64_t hash_key)
{
	link_list_node_t *node = link_list;
	link_list_node_t *match_node = NULL;


	while ((node = node->next) != NULL)
	{
		if (node->mapping_info->id == hash_key)
		{
			match_node = node;
		}
	}

	return match_node;
}

int link_list_delete_viamappinginfo (link_list_node_t *link_list, container_unixsocket_mapping_info_t *mapping_info)
{
	link_list_node_t *to_be_deleted_node = NULL;

	to_be_deleted_node = link_list_search_viahashkey (link_list, mapping_info->id);

	if (to_be_deleted_node == NULL)
	{
		return 0;
	}

	to_be_deleted_node->previous->next = to_be_deleted_node->next;
	to_be_deleted_node->next->previous = to_be_deleted_node->previous;

	free (to_be_deleted_node);

	return 1;
}

int link_list_delete_viahashkey (link_list_node_t *link_list, uint64_t hash_key)
{
	link_list_node_t *to_be_deleted_node = NULL;

	to_be_deleted_node = link_list_search_viahashkey (link_list, hash_key);

	if (to_be_deleted_node == NULL)
	{
		return 0;
	}

	to_be_deleted_node->previous->next = to_be_deleted_node->next;

	if (to_be_deleted_node->next != NULL)
	{
		to_be_deleted_node->next->previous = to_be_deleted_node->previous;
	}

	free (to_be_deleted_node);

	return 1;
}

void link_list_node_init (link_list_node_t *node)
{
	node->mapping_info = NULL;
	node->previous = NULL;
	node->next = NULL;
}

uint64_t get_hash_key (uint32_t ip, uint16_t port)
{
	uint64_t key;
	uint64_t ip_uint64;
	uint64_t ip_left_shift_16;

	ip_uint64 = ip;
	ip_left_shift_16 = ip_uint64 << 16;
	key = ip_left_shift_16 ^ port;

	return key;
}

link_list_node_t *link_list_search_viaipport (link_list_node_t *link_list, uint32_t ip, uint16_t port)
{
	uint64_t hash_key;

	hash_key = get_hash_key (ip, port);

	return link_list_search_viahashkey (link_list, hash_key);
}

void hash_table_init (hash_table_slot_t **hash_table, size_t hash_table_size)
{
	link_list_node_t *node = NULL;

	for (int i = 0; i < hash_table_size; i++)
	{
		node = (link_list_node_t*) malloc (sizeof (link_list_node_t));
		link_list_node_init (node);
		hash_table[i] = node;
	}
}

uint32_t get_hash_index_viahashkey (uint64_t hash_key)
{
	uint32_t hash_index;

	hash_index = hash_key % HASHSIZE;
	return hash_index;
}

uint32_t get_hash_index_viaipport (uint32_t ip, uint16_t port)
{
	uint64_t hash_key;
	uint32_t hash_index;

	hash_key = get_hash_key (ip, port);
	hash_index = get_hash_index_viahashkey (hash_key);

	return hash_index;
}

void hash_table_insert (hash_table_slot_t **hash_table, container_unixsocket_mapping_info_t *mapping_info)
{
	uint32_t hash_index;

	mapping_info->id = get_hash_key (mapping_info->listening_address, mapping_info->listening_port);
	hash_index = get_hash_index_viaipport (mapping_info->listening_address, mapping_info->listening_port);

	link_list_insert (hash_table[hash_index], mapping_info);
}

link_list_node_t *hash_table_search_viahashkey (hash_table_slot_t **hash_table, uint64_t hash_key)
{
	uint32_t hash_index;

	hash_index = get_hash_index_viahashkey (hash_key);

	return link_list_search_viahashkey (hash_table[hash_index], hash_key);
}

link_list_node_t *hash_table_search_viaipport (hash_table_slot_t **hash_table, uint32_t ip, uint16_t port)
{
	uint32_t hash_index;

	hash_index = get_hash_index_viaipport (ip, port);

	return link_list_search_viaipport (hash_table[hash_index], ip, port);
}

void hash_table_delete_viahashkey (hash_table_slot_t **hash_table, uint64_t hash_key)
{
	uint32_t hash_index;

	hash_index = get_hash_index_viahashkey (hash_key);

	link_list_delete_viahashkey (hash_table[hash_index], hash_key);
}

void hash_table_delete_viaipport (hash_table_slot_t **hash_table, uint32_t ip, uint16_t port)
{
	uint64_t hash_key;
	uint32_t hash_index;

	hash_key = get_hash_key (ip, port);

	hash_table_delete_viahashkey (hash_table, hash_key);
}

void hash_table_output_traverse (hash_table_slot_t **hash_table, uint32_t hash_size)
{
	link_list_node_t *node = NULL;
	for (int i = 0; i < hash_size; i++)
	{
		node = hash_table[i];
		while ((node = node->next) != NULL)
		{
			printf ("hash index: %d, ip->%d, port->%d, unixsocket_server->%d, unixsocket_client->%d\n",
			        i, node->mapping_info->listening_address, node->mapping_info->listening_port, 
			        node->mapping_info->unixsocket_server, node->mapping_info->unixsocket_client);
		}
	}
}
