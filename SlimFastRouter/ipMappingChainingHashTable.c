#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>

#include "ipMappingChainingHashTable.h"

void ip_mapping_link_list_node_init (ip_mapping_link_list_node_t *node)
{
	node->mapping_info = NULL;
	node->previous = NULL;
	node->next = NULL;
}

void ip_mapping_link_list_insert (ip_mapping_link_list_node_t *link_list, ip_mapping_info_t *mapping_info)
{
	/* head insert: two-way linked list*/
    ip_mapping_link_list_node_t *node = (ip_mapping_link_list_node_t*) malloc (sizeof (ip_mapping_link_list_node_t));

    node->mapping_info = mapping_info;

    if (link_list->next != NULL)
    {
    	link_list->next->previous = node;
    }

    node->previous = link_list;
    node->next = link_list->next;
    link_list->next = node;
}

void ip_mapping_hash_table_init (ip_mapping_hash_table_slot_t **hash_table, size_t hash_table_size)
{
	ip_mapping_link_list_node_t *node = NULL;

	for (int i = 0; i < hash_table_size; i++)
	{
		node = (ip_mapping_link_list_node_t*) malloc (sizeof (ip_mapping_link_list_node_t));
		ip_mapping_link_list_node_init (node);
		hash_table[i] = node;
	}
}


uint32_t ip_mapping_get_hash_index_viaip (uint32_t container_ip)
{
	uint32_t hash_index;

	hash_index = container_ip % IPMAPPING_HASHSIZE;
	return hash_index;
}


void ip_mapping_hash_table_insert (ip_mapping_hash_table_slot_t **hash_table, ip_mapping_info_t *mapping_info)
{
	uint32_t hash_index;

	hash_index = ip_mapping_get_hash_index_viaip (mapping_info->container_ip);

	ip_mapping_link_list_insert (hash_table[hash_index], mapping_info);
}


ip_mapping_link_list_node_t *ip_mapping_link_list_search_viaip (ip_mapping_link_list_node_t *link_list, uint32_t container_ip)
{
	ip_mapping_link_list_node_t *node = link_list;
	ip_mapping_link_list_node_t *match_node = NULL;

	while ((node = node->next) != NULL)
	{
		if (node->mapping_info->container_ip == container_ip)
		{
			match_node = node;
		}
	}

	return match_node;
}

ip_mapping_link_list_node_t *ip_mapping_hash_table_search_viaip (ip_mapping_hash_table_slot_t **hash_table, uint32_t container_ip)
{
	uint32_t hash_index;

	hash_index = ip_mapping_get_hash_index_viaip (container_ip);

	return ip_mapping_link_list_search_viaip (hash_table[hash_index], container_ip);
}


int ip_mapping_link_list_delete_viaip (ip_mapping_link_list_node_t *link_list, uint32_t container_ip)
{
	ip_mapping_link_list_node_t *to_be_deleted_node = NULL;

	to_be_deleted_node = ip_mapping_link_list_search_viaip (link_list, container_ip);

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

void ip_mapping_hash_table_delete_viaip (ip_mapping_hash_table_slot_t **hash_table, uint32_t container_ip)
{
	uint32_t hash_index;

	hash_index = ip_mapping_get_hash_index_viaip (container_ip);

	ip_mapping_link_list_delete_viaip (hash_table[hash_index], container_ip);
}


void ip_mapping_hash_table_output_traverse (ip_mapping_hash_table_slot_t **hash_table, uint32_t hash_size)
{
	ip_mapping_link_list_node_t *node = NULL;
	for (int i = 0; i < hash_size; i++)
	{
		node = hash_table[i];
		while ((node = node->next) != NULL)
		{
			printf ("hash index: %d, container_ip->%d, host_ip->%d\n",
			        i, node->mapping_info->container_ip, node->mapping_info->host_ip);
		}
	}
}













