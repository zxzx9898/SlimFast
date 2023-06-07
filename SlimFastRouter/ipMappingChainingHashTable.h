#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>

#define IPMAPPING_HASHSIZE 1023

typedef struct ip_mapping_info_s
{
    uint32_t container_ip;
    uint32_t host_ip;
}ip_mapping_info_t;

typedef struct ip_mapping_link_list_node_s
{
    ip_mapping_info_t *mapping_info;
    struct ip_mapping_link_list_node_s *previous;
    struct ip_mapping_link_list_node_s *next;
}ip_mapping_link_list_node_t, ip_mapping_hash_table_slot_t;


void ip_mapping_link_list_node_init (ip_mapping_link_list_node_t *node);

void ip_mapping_link_list_insert (ip_mapping_link_list_node_t *link_list, ip_mapping_info_t *mapping_info);

void ip_mapping_hash_table_init (ip_mapping_hash_table_slot_t **hash_table, size_t hash_table_size);


uint32_t ip_mapping_get_hash_index_viaip (uint32_t container_ip);


void ip_mapping_hash_table_insert (ip_mapping_hash_table_slot_t **hash_table, ip_mapping_info_t *mapping_info);


ip_mapping_link_list_node_t *ip_mapping_link_list_search_viaip (ip_mapping_link_list_node_t *link_list, uint32_t container_ip);

ip_mapping_link_list_node_t *ip_mapping_hash_table_search_viaip (ip_mapping_hash_table_slot_t **hash_table, uint32_t container_ip);


int ip_mapping_link_list_delete_viaip (ip_mapping_link_list_node_t *link_list, uint32_t container_ip);

void ip_mapping_hash_table_delete_viaip (ip_mapping_hash_table_slot_t **hash_table, uint32_t container_ip);


void ip_mapping_hash_table_output_traverse (ip_mapping_hash_table_slot_t **hash_table, uint32_t hash_size);

