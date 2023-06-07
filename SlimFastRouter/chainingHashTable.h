#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>

#define HASHSIZE 1023

typedef struct container_unixsocket_mapping_info_s
{
    uint64_t id;
    uint32_t listening_address;
    uint16_t listening_port;
    uint32_t unixsocket_server;
    uint32_t unixsocket_client;
}container_unixsocket_mapping_info_t;

typedef struct link_list_node_s
{
    container_unixsocket_mapping_info_t *mapping_info;
    struct link_list_node_s *previous;
    struct link_list_node_s *next;
}link_list_node_t, hash_table_slot_t;


void link_list_insert (link_list_node_t *link_list, container_unixsocket_mapping_info_t *mapping_info);

link_list_node_t *link_list_search_viahashkey (link_list_node_t *link_list, uint64_t hash_key);

int link_list_delete_viamappinginfo (link_list_node_t *link_list, container_unixsocket_mapping_info_t *mapping_info);

int link_list_delete_viahashkey (link_list_node_t *link_list, uint64_t hash_key);

void link_list_node_init (link_list_node_t *node);

uint64_t get_hash_key (uint32_t ip, uint16_t port);

link_list_node_t *link_list_search_viaipport (link_list_node_t *link_list, uint32_t ip, uint16_t port);

void hash_table_init (hash_table_slot_t **hash_table, size_t hash_table_size);

uint32_t get_hash_index_viahashkey (uint64_t hash_key);

uint32_t get_hash_index_viaipport (uint32_t ip, uint16_t port);

void hash_table_insert (hash_table_slot_t **hash_table, container_unixsocket_mapping_info_t *mapping_info);

link_list_node_t *hash_table_search_viahashkey (hash_table_slot_t **hash_table, uint64_t hash_key);

link_list_node_t *hash_table_search_viaipport (hash_table_slot_t **hash_table, uint32_t ip, uint16_t port);

void hash_table_delete_viahashkey (hash_table_slot_t **hash_table, uint64_t hash_key);

void hash_table_delete_viaipport (hash_table_slot_t **hash_table, uint32_t ip, uint16_t port);

void hash_table_output_traverse (hash_table_slot_t **hash_table, uint32_t hash_size);
