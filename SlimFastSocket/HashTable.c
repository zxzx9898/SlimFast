#include "HashTable.h"

#define TABLE_SIZE 2029
#define debug_flag 0

hash_table_t *create_hash_table() {
    hash_table_t *ht = (hash_table_t *)malloc( sizeof(hash_table_t) );
    if ( ht==NULL )
        return NULL;
    ht->buckets = (hash_node_t **)calloc(TABLE_SIZE, sizeof(hash_node_t *));
    return ht;
}

int hash_function(uint64_t key) {
    return key % TABLE_SIZE;
}

void hash_table_insert(hash_table_t *ht, uint64_t key, uint32_t addr, uint16_t port) {
    int index = hash_function(key);
    hash_node_t *node = (hash_node_t *)malloc(sizeof(hash_node_t));
    node->key = key;
    node->m_addr = addr;
    node->m_port = port;
    node->next = ht->buckets[index];
    ht->buckets[index] = node;
}

hash_node_t *hash_table_search(hash_table_t *ht, uint64_t key) {
    int index = hash_function(key);
    hash_node_t *node = ht->buckets[index];
    while (node != NULL) {
        if ( node->key == key) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}


void hash_table_delete(hash_table_t *ht, uint64_t key) {
    int index = hash_function(key);
    hash_node_t *node = ht->buckets[index];
    hash_node_t *prev = NULL;
    while (node != NULL) {
        if ( node->key == key ) {
            if (prev == NULL) {
                ht->buckets[index] = node->next;
            } else {
                prev->next = node->next;
            }
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}


void hash_table_print(hash_table_t *ht) {
    struct in_addr addr;
    for (int i = 0; i < TABLE_SIZE; i++) {
        hash_node_t *node = ht->buckets[i];
        while (node != NULL) {
            addr.s_addr = htonl(node->m_addr);
            node = node->next;
        }
    }
}

void free_hash_node(hash_node_t *node) {
    if (node == NULL) {
        return;
    }

    free_hash_node(node->next);
    free(node);
}

void free_hash_table(hash_table_t *ht) {
    if (ht == NULL) {
        return;
    }

    for (int i = 0; i < TABLE_SIZE; i++) {
        free_hash_node(ht->buckets[i]);
    }

    free(ht->buckets);
    free(ht);
}