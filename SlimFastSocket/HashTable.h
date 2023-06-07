#if !defined(HashTable_H)
#define HashTable_H
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define TABLE_SIZE 2029


typedef struct hash_node {
    uint64_t key;
    uint32_t m_addr;
    uint16_t m_port;
    struct hash_node *next;
} hash_node_t;

typedef struct hash_table {
    hash_node_t **buckets;
} hash_table_t;

hash_table_t *create_hash_table();


int hash_function(uint64_t key);
void hash_table_insert(hash_table_t *ht, uint64_t key, uint32_t addr, uint16_t port);
hash_node_t *hash_table_search(hash_table_t *ht, uint64_t key);
void hash_table_delete(hash_table_t *ht, uint64_t key);
void hash_table_print(hash_table_t *ht);
void free_hash_node(hash_node_t *node);
void free_hash_table(hash_table_t *ht);