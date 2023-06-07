// #define SECURITY

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/epoll.h>
#include <time.h> 
#include <fcntl.h>
#include <semaphore.h>

#include "timeDiff.h"
#include "tpool.h"
#include "chainingHashTable.h"
#include "ipMappingChainingHashTable.h"
#include <sys/wait.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include "HashTable.h"

#define USE_THREAD_POOL true
#define USE_TCP_MODE false
#define debug_flag false
int test_mod = 0;

// #ifdef SECURITY
#include "crypto.hpp"

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

// #endif

extern "C" {
#include "ops.h"
}

using std::cout;
using std::endl;

using std::string;

sem_t semaphore;

typedef struct security_mode_host_fd_s
{
    int host_fd;
}security_mode_host_fd_t;


class SlimKern {
    static const string kern_dup_path;
    static const string kern_filter_path;
    static const string kern_revoke_path;

    int dup_fd;
    int revoke_fd;
    int filter_fd;

    void send_cmd_to_kern(int fd, void *ptr, size_t size) {
         int ret = write(fd, ptr, size);
       if (ret < 0) {
         assert(false && "oops");
          }
    }

public:
    SlimKern() {
        dup_fd = open(kern_dup_path.c_str(), O_RDWR);
        revoke_fd = open(kern_revoke_path.c_str(), O_RDWR);
        filter_fd = open(kern_filter_path.c_str(), O_RDWR);

        if (dup_fd < 0 || revoke_fd < 0 || filter_fd < 0) {
               assert(false && "oops: open kernel module failed");
          }
    }

    ~SlimKern() {
         close(dup_fd);
         close(revoke_fd);
         close(filter_fd);
    }

    void add_filter_fd(pid_t pid, int fd) {
    struct FilterOp op;
    op.op = FILTER_OP_ADD_FD;
    op.pid = pid;
    op.fd = fd;
    send_cmd_to_kern(filter_fd, (void *)&op, sizeof(op));
    }

    void remove_filter_fd(pid_t pid, int fd) {
    struct FilterOp op;
    op.op = FILTER_OP_REMOVE_FD;
    op.pid = pid;
    op.fd = fd;
    send_cmd_to_kern(filter_fd, (void *)&op, sizeof(op));
    }

    void dup2(pid_t pid_src, int src, pid_t pid_dst, int dst) {
    struct DupOp op;
    op.pid_dst = pid_dst;
    op.fd_dst = dst;
    op.pid_src = pid_src;
    op.fd_src = src;
    send_cmd_to_kern(dup_fd, (void *)&op, sizeof(op));
    }

    void revoke(pid_t pid, int fd) {
    struct Cmd op;
    op.pid = pid;
    op.fd = fd;
    send_cmd_to_kern(revoke_fd, (void *)&op, sizeof(op));
    }
};

const string SlimKern::kern_dup_path = "/proc/dup2_helper";
const string SlimKern::kern_filter_path = "/proc/filter_manage";
const string SlimKern::kern_revoke_path = "/proc/fd_remover";

#ifdef SECURITY
SlimKern kern_mod;
AESgcm cipher(gcm_key, gcm_iv, 128, sizeof(gcm_iv));
#endif


// typedef enum __bool { false = 0, true = 1, } bool;


#define UNIX_SOCKET_PATH "SlimFastRouter"

#define MSG_SOCKET_INVOKE_REQUEST   0
#define MSG_BIND_INVOKE_REQUEST     1
#define MSG_LISTEN_INVOKE_REQUEST   2
#define MSG_CONNECT_INVOKE_REQUEST  3
#define MSG_ACCEPT_INVOKE_REQUEST   4
#define MSG_ACCEPT4_INVOKE_REQUEST  5
#define MSG_INSERT_INVOKE_REQUEST   6
#define MSG_SEARCH_HOST_ADDR_INVOKE_REQUEST   7
#define MSG_SEARCH_CLIENT_INVOKE_REQUEST   8

#define DEBUG false  //lfs

#define BLOCK_FLAG    0x00000002
#define NONBLOCK_FLAG 0x00000802



#define LISTEN_FD 1
#define SERVER_FD 2
#define CLIENT_FD 3
#define LISTEN_PORT 9999

#define SOCKET_FILE "SlimFastUDPRouter"

uint8_t fd_table[65536] = {0}; 
hash_table_t *client_host_info;  
hash_table_t *listen_server_host_info; 
pthread_mutex_t client_host_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t listen_server_host_table_mutex = PTHREAD_MUTEX_INITIALIZER;

hash_table_slot_t *hash_table[HASHSIZE];
ip_mapping_hash_table_slot_t *ip_mapping_hash_table[IPMAPPING_HASHSIZE];

int listenfd_arr[20] = {8888, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896, 8897, 8898, 8899, 8900, 8901, 8902, 8903, 8904,8905, 8906, 8907};
int listen_thrd_num = 1;

tpool_t *connect_to_server_router_tpool = NULL;
tpool_t *host_tcp_server_send_fd_tpool = NULL;
tpool_t *uds_server_epoll_event_tpool = NULL;
tpool_t *tcp_server_epoll_event_tpool = NULL;

int connect_to_server_router_tpool_tnumber = 10;
int host_tcp_server_send_fd_tpool_tnumber = 10;


int uds_server_epoll_event_tpool_tnumber = 10; 
int tcp_server_epoll_event_tpool_tnumber = 10; 



// ==================================================================

FILE *router_socket_fp;
FILE *router_connect_fp;


// socket invoke
struct timeval uds_server_thrd__accept_tvStart, uds_server_thrd__accept_tvEnd;
struct timeval uds_server_epoll_event_thrd__recv_tvStart, uds_server_epoll_event_thrd__recv_tvEnd;
struct timeval connect_to_server_router_thrd_SOCKET_INVOKE__socket_tvStart, connect_to_server_router_thrd_SOCKET_INVOKE__socket_tvEnd;
struct timeval connect_to_server_router_thrd_SOCKET_INVOKE__send_fd_tvStart, connect_to_server_router_thrd_SOCKET_INVOKE__send_fd_tvEnd;


double time_diff_uds_server_thrd__accept;
double time_diff_uds_server_epoll_event_thrd__recv;
double time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__socket;
double time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__send_fd;


struct timeval create_uds_server_epoll_event_thrd_tvStart, create_uds_server_epoll_event_thrd_tvEnd; 

double time_diff_create_uds_server_epoll_event_thrd;

struct timeval epoll_ctl_tvStart, epoll_ctl_tvEnd;

double time_diff_epoll_ctl;

// connect invoke

struct timeval connect_to_server_router_thrd__ip_mapping_search_tvStart, connect_to_server_router_thrd__ip_mapping_search_tvEnd;
struct timeval connect_to_server_router_thrd__recv_fd_tvStart, connect_to_server_router_thrd__recv_fd_tvEnd;
struct timeval connect_to_server_router_thrd__connect_tvStart, connect_to_server_router_thrd__connect_tvEnd;
struct timeval connect_to_server_router_thrd__send_tvStart, connect_to_server_router_thrd__send_tvEnd;
struct timeval connect_to_server_router_thrd__send_fd_tvStart, connect_to_server_router_thrd__send_fd_tvEnd;

struct timeval host_tcp_server_send_fd_thrd__hash_table_search_viaipport_tvStart, host_tcp_server_send_fd_thrd__hash_table_search_viaipport_tvEnd;


double time_diff_connect_to_server_router_thrd__ip_mapping_search;
double time_diff_connect_to_server_router_thrd__recv_fd;
double time_diff_connect_to_server_router_thrd__connect;
double time_diff_connect_to_server_router_thrd__send;
double time_diff_connect_to_server_router_thrd__send_fd;

double time_diff_host_tcp_server_send_fd_thrd__hash_table_search_viaipport;

// ==================================================================

typedef struct msg_s
{
    uint16_t msg_type;
    uint32_t listening_addr;
    uint16_t listening_port;
    uint32_t unix_sock;
    uint32_t fd_number;
}msg_t;

typedef struct socket_info 
{
    uint8_t req_type;
    uint64_t hash_key;
    uint32_t m_addr;
    uint16_t m_port;
}hash_msg;

typedef struct uds_server_epoll_event_thrd_args_s
{
    int server_sock;
    int event_fd;
    int epoll_fd;
    int accept_fd;
    int fd_number;
}uds_server_epoll_event_thrd_args_t;

typedef struct tcp_server_epoll_event_thrd_args_s
{
    int server_sock;
    int event_fd;
    int epoll_fd;
    int accept_fd;
}tcp_server_epoll_event_thrd_args_t, udp_router_epoll_event_thrd_args_t;

typedef struct udp_listen_router_epoll_event_thrd_args
{
    int                 listening_socket;
    char *              buf;
    size_t              n;
    int                 flags;
    struct sockaddr *   addr;
    socklen_t           addr_len;
}udp_listen_router_epoll_event_thrd_args_t;

void init_ip_mapping_hash_table (ip_mapping_hash_table_slot_t **hash_table)
{
    ip_mapping_hash_table_init (hash_table, IPMAPPING_HASHSIZE);

    ip_mapping_info_t *mapping_info = (ip_mapping_info_t *) malloc (sizeof (ip_mapping_info_t));

    struct sockaddr_in container_addr = {0};
    struct sockaddr_in host_addr = {0};

    container_addr.sin_family = AF_INET;       
    host_addr.sin_family = AF_INET;      

    if (inet_aton ("10.44.0.0", (struct in_addr*) (&container_addr.sin_addr.s_addr)) == -1)
    {
        printf("inet_aton error!\n");
    }

    if (inet_aton ("10.0.9.1", (struct in_addr*) (&host_addr.sin_addr.s_addr)) == -1)
    {
        printf("inet_aton error!\n");
    }

    mapping_info->container_ip = ntohl (container_addr.sin_addr.s_addr);
    mapping_info->host_ip = ntohl (host_addr.sin_addr.s_addr);

    ip_mapping_hash_table_insert (hash_table, mapping_info);
}

int recv_fd(int unix_sock)
{
    ssize_t size;
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr cmsghdr;
        char control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr *cmsg;
    char buf[2];
    int fd = -1;

    iov.iov_base = buf;
    iov.iov_len = 2;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);
    size = recvmsg (unix_sock, &msg, 0);

    if (size < 0) {
        printf ("recvmsg error: %s\n", strerror (errno));
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmsg->cmsg_level != SOL_SOCKET) {
            fprintf (stderr, "invalid cmsg_level %d\n",
                    cmsg->cmsg_level);
            printf("invalid cmsg_level\n");
            return -1;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) {
            fprintf (stderr, "invalid cmsg_type %d\n",
                    cmsg->cmsg_type);
            printf("invalid cmsg_type\n");
            return -1;
        }
        int *fd_p = (int *)CMSG_DATA(cmsg);
        fd = *fd_p;
        
    } else {
        fd = -1;
    }
    if ( DEBUG )
        printf ("received fd %d\n", fd);
    return(fd);
}

int send_fd(int sock, int fd)
{
    if (DEBUG)
    {
        printf("start send fd %d\n", fd);
    }
    ssize_t     size;
    struct msghdr   msg;
    struct iovec    iov;
    union {
        struct cmsghdr  cmsghdr;
        char        control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr  *cmsg;
    char buf[2];

    iov.iov_base = buf;
    iov.iov_len = 2;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (fd != -1) {
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof (int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        *((int *) CMSG_DATA(cmsg)) = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    size = sendmsg(sock, &msg, 0);

    if (size < 0) {
        perror ("sendmsg");
    }

    return size;
}

void store_uds_map_info (int unix_sock, msg_t *msg, hash_table_slot_t *hash_table)
{
    container_unixsocket_mapping_info_t *mapping_info = (container_unixsocket_mapping_info_t *) malloc (sizeof (container_unixsocket_mapping_info_t));
    mapping_info->listening_address = msg->listening_addr; 
    mapping_info->listening_port = msg->listening_port;
    mapping_info->unixsocket_server = unix_sock;
    mapping_info->unixsocket_client = msg->unix_sock;

    hash_table_insert ((hash_table_slot_t**)(hash_table), mapping_info);
}

typedef struct host_tcp_server_send_fd_thrd_args_s
{
    int connfd;
}host_tcp_server_send_fd_thrd_args_t;

void host_tcp_server_send_fd (void *args)
{
    struct timeval tvStart,tvEnd;
    gettimeofday(&tvStart,NULL);
    host_tcp_server_send_fd_thrd_args_t *host_tcp_server_send_fd_thrd_args = (host_tcp_server_send_fd_thrd_args_t *) args;

    int connfd = host_tcp_server_send_fd_thrd_args->connfd;

    char buff[20];

    int n = recv(connfd, buff, 20, 0);

    msg_t *msg = (msg_t*) buff;

    if (msg->msg_type == MSG_CONNECT_INVOKE_REQUEST)
    {
        if (DEBUG)
        {
            printf("host_tcp_server_thrd(): recv msg type->MSG_HOST_SOCKET_REQUEST\n");
            printf("host_tcp_server_thrd(): listening_addr: %d, listening_port: %d, unix_sock: %d\n", msg->listening_addr, msg->listening_port, msg->unix_sock);
        }

        // search corresponding unix domain socket

        link_list_node_t *node = hash_table_search_viaipport (hash_table, msg->listening_addr, msg->listening_port);

        int unix_socket = node->mapping_info->unixsocket_server;

        // // printf("hash_table_search_viaipport unix_socket: %d\n", unix_socket);

        if (unix_socket == -1)
        {
            printf("seach_corresponding_unix_domain_socket error!!!\n");
        }
        else
        {
            if (DEBUG)
            {
                printf("host_tcp_server_thrd(): unix_socket->%d\n", unix_socket);
            }
            send_fd (unix_socket, connfd); 
            close (connfd);
        }
    }
    gettimeofday(&tvEnd,NULL);
    double time_elapsed = time_diff (tvStart,tvEnd);
    if (DEBUG)
    {
        printf ("host_tcp_server_send_fd_thrd()->comsume time: %f us\n", time_elapsed);   
    }
}

void print_interface_addresses() {
    struct ifaddrs *ifaddr, *ifa;
    char ip_addr[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, ip_addr, INET_ADDRSTRLEN);
            uint32_t ip = ntohl(addr->sin_addr.s_addr);
            printf("%s: %s\n", ifa->ifa_name, ip_addr);
        }
    }

    freeifaddrs(ifaddr);
}

uint64_t GetHash(uint32_t ip, uint16_t port)
{
    uint64_t key;
    uint64_t ip_uint64;
    uint64_t ip_left_shift_16;

    ip_uint64 = ip;
    ip_left_shift_16 = ip_uint64 << 16;
    key = ip_left_shift_16 ^ port;

    return key;
}

uint64_t GetHashViaPacket(void *buf)
{
    char* recv_buf;
    char* temp_buf;
    recv_buf = (char*)malloc(strlen((char *)buf)+1);
    memset(recv_buf, 0, strlen((char *)buf)+1);
    strcpy(recv_buf, (char *)buf);
    char hash_key[21];
    // char *prt_t = buf;
    int len = 0;
    while( *(char *)recv_buf&&*(char *)recv_buf!='*' )
    {
        hash_key[len++] = *(char *)recv_buf;
        recv_buf++;
    }
    recv_buf++;
    hash_key[len] = '\0';
    if ( debug_flag )
        printf("GetHashViaPacket (char)hash_key %s\n", hash_key);
    recv_buf[strlen((char *)buf)-strlen(hash_key)-1] = '\0';
    strcpy((char *)buf, recv_buf);

    uint64_t hash_num = strtol((char *)hash_key, &temp_buf, 10);
    return hash_num;
}

void InsertHashToPacket(void **buf, size_t msg_len, uint64_t hash)
{
    char* sendto_buf;
    char hash_key[21];
    snprintf (hash_key, sizeof(hash_key), "%ld%s",hash, "*");

    sendto_buf = (char*)malloc(strlen(hash_key) + msg_len + 1);
    memset(sendto_buf, 0, strlen(hash_key) + msg_len + 1);

    strcpy(sendto_buf, hash_key);
    memcpy(sendto_buf + strlen(hash_key), *buf, msg_len); 

    // free(*buf);
    *buf = sendto_buf;
}

ssize_t RouterSend(int socket, void *buf, size_t msg_len, int flags, const struct sockaddr *to, socklen_t tolen, uint64_t client_hash_key)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)to;

    void *sendto_buf = buf;
    InsertHashToPacket(&sendto_buf, msg_len, client_hash_key);
    int ret = sendto(socket, sendto_buf, strlen((char *)sendto_buf) + 1, flags, (struct sockaddr *)sin, tolen);
    return ret - (strlen((char *)sendto_buf) - msg_len);
}

//
void *host_tcp_server_send_fd_thrd (void *args)
{
    struct timeval tvStart,tvEnd;
    gettimeofday(&tvStart,NULL);
    host_tcp_server_send_fd_thrd_args_t *host_tcp_server_send_fd_thrd_args = (host_tcp_server_send_fd_thrd_args_t *) args;

    int connfd = host_tcp_server_send_fd_thrd_args->connfd;

    char buff[20];

    if (DEBUG)
    {
        printf("connect fd: %d\n", connfd);
    }
    int n = recv(connfd, buff, 20, 0); 
    if (n <= 0)
    {
        printf("host_tcp_server_send_fd_thrd recv error: rece bytes: %d, %s\n", n, strerror (errno));
    }
    if (DEBUG)
    {
        printf("tcp server recv bytes: %d\n", n);
        printf("tcp server recv data: %s\n", buff);
    }

    msg_t *msg = (msg_t*) buff;

    if (msg->msg_type == MSG_CONNECT_INVOKE_REQUEST)
    {
        if (DEBUG)
        {
            printf("host_tcp_server_thrd(): recv msg type->MSG_HOST_SOCKET_REQUEST\n");
            printf("host_tcp_server_thrd(): listening_addr: %d, listening_port: %d, unix_sock: %d\n", msg->listening_addr, msg->listening_port, msg->unix_sock);
        }

        // search corresponding unix domain socket

        // gettimeofday (&host_tcp_server_send_fd_thrd__hash_table_search_viaipport_tvStart, NULL);  // time diff
        link_list_node_t *node = hash_table_search_viaipport (hash_table, msg->listening_addr, msg->listening_port);
        // gettimeofday (&host_tcp_server_send_fd_thrd__hash_table_search_viaipport_tvEnd, NULL);  // time diff

        // time_diff_host_tcp_server_send_fd_thrd__hash_table_search_viaipport = time_diff (host_tcp_server_send_fd_thrd__hash_table_search_viaipport_tvStart, host_tcp_server_send_fd_thrd__hash_table_search_viaipport_tvEnd);  // time diff

        // fprintf (router_connect_fp, "time_diff_host_tcp_server_send_fd_thrd__hash_table_search_viaipport,%lf\n", time_diff_host_tcp_server_send_fd_thrd__hash_table_search_viaipport);  // time diff
        // fflush (router_connect_fp);  // time diff

        int unix_socket = node->mapping_info->unixsocket_server; //

        // // printf("hash_table_search_viaipport unix_socket: %d\n", unix_socket);

        if (unix_socket == -1)
        {
            printf("seach_corresponding_unix_domain_socket error!!!\n");
        }
        else
        {
            if (DEBUG)
            {
                printf("host_tcp_server_thrd(): unix_socket->%d\n", unix_socket);
            }


#ifdef SECURITY
            char recv_buf[50];
            unsigned int ucred_len;
            struct ucred ucred;
            ucred_len = sizeof(struct ucred);
            if (getsockopt(unix_socket, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                printf("getsockopt failed\n");
                // return;
            }

            send_fd (unix_socket, connfd);

            // printf("before recv\n");

            if (recv (unix_socket, recv_buf, sizeof (security_mode_host_fd_t), 0) <= 0)
            {
            	printf("security mode recv error: %s\n", strerror (errno));
            }

            int host_fd = ((security_mode_host_fd_t*)recv_buf)->host_fd;

            // printf("host_fd: %d\n", host_fd);

            // printf("ucred.pid: %d\n", ucred.pid);

            kern_mod.add_filter_fd(ucred.pid, host_fd);


            // sleep (30);
            // kern_mod.revoke(ucred.pid, host_fd);
            // printf("call revoke done\n");

            if (send (unix_socket, "12345", 5, 0) <= 0)
            {
            	printf("security mode send error: %s\n", strerror (errno));
            }

               
#endif

#ifndef SECURITY

            send_fd (unix_socket, connfd);
            // // printf("send fd->connfd: %d\n", connfd);

#endif
            close (connfd);



        }
    }
    gettimeofday(&tvEnd,NULL);
    double time_elapsed = time_diff (tvStart,tvEnd);

    return NULL; 
}

void *tcp_server_epoll_event_thrd (void *args)
{
    struct epoll_event ev;

    int server_sock = ((tcp_server_epoll_event_thrd_args_t*) args)->server_sock;
    int event_fd = ((tcp_server_epoll_event_thrd_args_t*) args)->event_fd;
    int epoll_fd = ((tcp_server_epoll_event_thrd_args_t*) args)->epoll_fd;
    int accept_fd = ((tcp_server_epoll_event_thrd_args_t*) args)->accept_fd;

    if (event_fd == server_sock)
    {
        ev.data.fd = accept_fd;
        ev.events = EPOLLIN;
  
        if (epoll_ctl(epoll_fd,EPOLL_CTL_ADD,accept_fd,&ev) == -1)
        {
            printf("tcp_server_epoll_event_thrd()->epoll_ctl(): EPOLL_CTL_ADD error: %s\n", strerror(errno));
        }
    }
    else
    {

        host_tcp_server_send_fd_thrd_args_t *args = (host_tcp_server_send_fd_thrd_args_t*) malloc (sizeof(host_tcp_server_send_fd_thrd_args_t));
        args->connfd = event_fd;
            // create_host_tcp_server_send_fd_thrd (args);
            // add_task_2_tpool (host_tcp_server_send_fd_tpool, host_tcp_server_send_fd_thrd, args);
        // // // printf("create_tcp_server_epoll_event_thrd->event fd: %d\n", event_fd);
        host_tcp_server_send_fd_thrd (args);
    }

    return NULL;
}

pthread_t create_tcp_server_epoll_event_thrd (tcp_server_epoll_event_thrd_args_t *args)
{
    pthread_t thread;

    int ret = pthread_create (&thread, NULL, tcp_server_epoll_event_thrd, args);
    if (ret != 0)
    {
        printf("create_tcp_server_epoll_event_thrd error: %s\n", strerror (errno));
    }

    return thread;
}

void *host_tcp_server_thrd (void *args)
{
    int port = *((int*) args);
    //create epoll 
    int epfd,eventfd;
    struct epoll_event ev,events[102400];
  
    epfd = epoll_create(102400);

    int  listenfd, connfd;
    struct sockaddr_in  servaddr;
    char  buff[4096];
    int  n;

    struct sockaddr clientaddr;
    socklen_t addrlen;
    if( (listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
        printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
        return 0;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    if (DEBUG)
        printf("tcp server listen on port: %d\n", port);

    ev.data.fd = listenfd;
    ev.events = EPOLLIN;
  
    if (epoll_ctl(epfd,EPOLL_CTL_ADD,listenfd,&ev) == -1)
    {
        printf("host_tcp_server_thrd()->epoll_ctl(): EPOLL_CTL_ADD1 error: %s\n", strerror(errno));
    }

    if( bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);
        return 0;
    }

    if( listen(listenfd, 102400) == -1){
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);
        return 0;
    }

    bool time_start = false;
    struct timeval tvStart,tvEnd;
    if (DEBUG)
        printf("======waiting for peer router's request======\n");
    while (1)
    {

        int nfds = epoll_wait(epfd,events,102400,-1);

        if (!time_start)
        {
            gettimeofday (&tvStart,NULL);
            time_start = true;
        }
       

      for(int i=0;i<nfds;i++)
      {
        if (DEBUG)
        {
            printf("host_tcp_server_thrd()->events[i].data.fd： %d\n", events[i].data.fd);
        }
        if(events[i].data.fd == listenfd)
        {

            if ((connfd = accept(listenfd, &clientaddr, &addrlen)) == -1) 
            {
                printf("accept socket error: %s(errno: %d)\n",strerror(errno),errno);
                break;
            }

        }
        else
        {
            if (epoll_ctl (epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL) == -1)
            {
                printf("host_tcp_server_thrd()->epoll_ctl(): EPOLL_CTL_DEL events[i].data.fd: %d error: %s\n", events[i].data.fd, strerror(errno));
            }
        }

        tcp_server_epoll_event_thrd_args_t *args = (tcp_server_epoll_event_thrd_args_t *) malloc (sizeof (tcp_server_epoll_event_thrd_args_t));
        args->server_sock = listenfd;
        args->event_fd = events[i].data.fd;
        args->epoll_fd = epfd;
        args->accept_fd = connfd;


        if (USE_THREAD_POOL)
        {
            add_task_2_tpool (tcp_server_epoll_event_tpool, tcp_server_epoll_event_thrd, args);
        }
        else
        {
            if (pthread_detach (create_tcp_server_epoll_event_thrd (args)) != 0)
            {
                printf("pthread_detach(create_tcp_server_epoll_event_thrd) error: %s\n", strerror (errno));
            }  
        }

    }
  }
    if (DEBUG)
        printf("======Close Router======\n");
    close(listenfd);

}


typedef struct connect_to_server_router_thrd_args_s
{
    char *recv_buf;
    int event_fd;
    int epoll_fd;
    int fd_number;
}connect_to_server_router_thrd_args_t;

void *connect_to_server_router_thrd (void *args)  
{
    connect_to_server_router_thrd_args_t *connect_to_server_router_thrd_args = (connect_to_server_router_thrd_args_t*) args;

    char *recv_buf = connect_to_server_router_thrd_args->recv_buf; 
    int event_fd = connect_to_server_router_thrd_args->event_fd;
    int epoll_fd = connect_to_server_router_thrd_args->epoll_fd;
    
  

        int   sockfd, n;
        char  recvline[4096], sendline[4096];
        struct sockaddr_in  servaddr;
        msg_t *msg = (msg_t*) recv_buf;
        int fd_number = msg->fd_number;

        if (msg->msg_type == MSG_SOCKET_INVOKE_REQUEST)
        {
            if (DEBUG)
            {
                printf("uds_server_thrd: receive msg_type-->MSG_SOCKET_INVOKE_REQUEST\n");
            }

            // gettimeofday(&connect_to_server_router_thrd_SOCKET_INVOKE__socket_tvStart,NULL);  // time diff
            if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
                return 0;
            }

            // gettimeofday(&connect_to_server_router_thrd_SOCKET_INVOKE__socket_tvEnd,NULL);  // time diff 
            // time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__socket = time_diff (connect_to_server_router_thrd_SOCKET_INVOKE__socket_tvStart, connect_to_server_router_thrd_SOCKET_INVOKE__socket_tvEnd);  // time diff

            // fprintf (router_socket_fp, "time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__socket,%lf\n", time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__socket);  // time diff

            if (DEBUG)
            {
                printf("sockfd: %d\n", sockfd);
            }
            // printf("prepare to send_fd\n");
            // gettimeofday(&connect_to_server_router_thrd_SOCKET_INVOKE__send_fd_tvStart,NULL);  // time diff
            send_fd (event_fd, sockfd); //那这里又是从哪里来的，发给谁——>发给SlimRouter生成的宿主机的socket
            // gettimeofday(&connect_to_server_router_thrd_SOCKET_INVOKE__send_fd_tvEnd,NULL);  // time diff
            // time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__send_fd = time_diff (connect_to_server_router_thrd_SOCKET_INVOKE__send_fd_tvStart, connect_to_server_router_thrd_SOCKET_INVOKE__send_fd_tvEnd);  // time diff

            // fprintf (router_socket_fp, "time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__send_fd,%lf\n", time_diff_connect_to_server_router_thrd_SOCKET_INVOKE__send_fd);  // time diff

            close (sockfd);
            close (event_fd);
        }
        if (msg->msg_type == MSG_BIND_INVOKE_REQUEST)
        {
            if (DEBUG)
            {
                printf("uds_server_thrd: receive msg_type-->MSG_BIND_INVOKE_REQUEST\n");
            }
            store_uds_map_info (event_fd, msg, (hash_table_slot_t*)hash_table);
            hash_table_output_traverse (hash_table, HASHSIZE);

            struct epoll_event ev;
            ev.data.fd = event_fd;
            ev.events = EPOLLIN;

        }
        if (msg->msg_type == MSG_CONNECT_INVOKE_REQUEST)
        {
            if (DEBUG)
            {
                printf("uds_server_thrd: receive msg_type-->MSG_CONNECT_INVOKE_REQUEST\n");
            }
            int port_index = rand () % listen_thrd_num;
            int port = listenfd_arr[port_index];

            // // printf("connect to server port: %d\n", port);

            memset(&servaddr, 0, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = htons(port);

            // printf("connect to port: %d\n", port);

            // gettimeofday (&connect_to_server_router_thrd__ip_mapping_search_tvStart, NULL);  // time diff
            ip_mapping_link_list_node_t *node = ip_mapping_hash_table_search_viaip (ip_mapping_hash_table, msg->listening_addr);
            // gettimeofday (&connect_to_server_router_thrd__ip_mapping_search_tvEnd, NULL);  // time diff

            // time_diff_connect_to_server_router_thrd__ip_mapping_search = time_diff (connect_to_server_router_thrd__ip_mapping_search_tvStart, connect_to_server_router_thrd__ip_mapping_search_tvEnd);  // time diff
            // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__ip_mapping_search,%lf\n", time_diff_connect_to_server_router_thrd__ip_mapping_search);  // time diff

            if (node == NULL)
            {
                printf("ip_mapping_hash_table_search_viaip error!\n");
            }

            servaddr.sin_addr.s_addr = htonl (node->mapping_info->host_ip);
            // gettimeofday (&connect_to_server_router_thrd__recv_fd_tvEnd, NULL);  // time diff
            // time_diff_connect_to_server_router_thrd__recv_fd = time_diff (connect_to_server_router_thrd__recv_fd_tvStart, connect_to_server_router_thrd__recv_fd_tvEnd);  // time diff
            // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__recv_fd,%lf\n", time_diff_connect_to_server_router_thrd__recv_fd);  // time diff
            if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            {
                printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
                return 0;
            }
            int flags = fcntl (sockfd, F_GETFL, 0);

            if (flags == NONBLOCK_FLAG)
            {
                if (fcntl(sockfd,F_SETFL,BLOCK_FLAG) == -1)
                {
                    printf("connect_to_server_router_thrd() fcntl error: %s\n", strerror (errno));
                }
                // printf("start connect1\n");
                // gettimeofday (&connect_to_server_router_thrd__connect_tvStart, NULL);  // time diff
                if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
                {
                    printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
                    return 0;                              
                }
                // printf("connect done1\n");
                // gettimeofday (&connect_to_server_router_thrd__connect_tvEnd, NULL);  // time diff

                // time_diff_connect_to_server_router_thrd__connect = time_diff (connect_to_server_router_thrd__connect_tvStart, connect_to_server_router_thrd__connect_tvEnd);  // time diff
                // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__connect,%lf\n", time_diff_connect_to_server_router_thrd__connect);  // time diff
            }
            else
            {
                // printf("start connect2\n");
                // gettimeofday (&connect_to_server_router_thrd__connect_tvStart, NULL);  // time diff
                if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
                {
                    printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
                    return 0;                          
                }
                // printf("connect done2\n");
                // gettimeofday (&connect_to_server_router_thrd__connect_tvEnd, NULL);  // time diff 
                // time_diff_connect_to_server_router_thrd__connect = time_diff (connect_to_server_router_thrd__connect_tvStart, connect_to_server_router_thrd__connect_tvEnd);  // time diff
                // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__connect,%lf\n", time_diff_connect_to_server_router_thrd__connect);  // time diff               
            }


#ifdef SECURITY


            int send_bytes = 0;
            // gettimeofday (&connect_to_server_router_thrd__send_tvStart, NULL);  // time diff
            if ((send_bytes = send (sockfd, recv_buf, sizeof (msg_t), 0)) < 0)
            {
                printf("udp server thrd(): send ip and port error!!!->%s\n", strerror (errno));
            }
            // gettimeofday (&connect_to_server_router_thrd__send_tvEnd, NULL);  // time diff
            // time_diff_connect_to_server_router_thrd__send = time_diff (connect_to_server_router_thrd__send_tvStart, connect_to_server_router_thrd__send_tvEnd);  // time diff
            // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__send,%lf\n", time_diff_connect_to_server_router_thrd__send);  // time diff


            char recv_buf_s[50];
            unsigned int ucred_len;
            struct ucred ucred;
            ucred_len = sizeof(struct ucred);
            if (getsockopt(event_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                printf("getsockopt failed\n");
                // return;
            }

            send_fd (event_fd, sockfd);

            if (recv (event_fd, recv_buf_s, sizeof (security_mode_host_fd_t), 0) <= 0)
            {
            	printf("security mode recv error: %s\n", strerror (errno));
            }



            int host_fd = ((security_mode_host_fd_t*)recv_buf_s)->host_fd;

            // printf("security mode recv host_fd: %d\n", host_fd);

            // printf("ucred.pid: %d\n", ucred.pid);

            kern_mod.add_filter_fd(ucred.pid, host_fd);

            if (send (event_fd, "12345", 5, 0) <= 0)
            {
            	printf("security mode send error: %s\n", strerror (errno));
            }

            // close (sockfd);

            // printf("revoke pid: %d, fd: %d in 30s later\n", ucred.pid, host_fd);
            // sleep (30);
            // kern_mod.revoke(ucred.pid, host_fd);
            // printf("revoke done\n");
               
#endif

 #ifndef SECURITY

            int send_bytes = 0;

            if ((send_bytes = send (sockfd, recv_buf, sizeof (msg_t), 0)) < 0)
            {
                printf("tcp server thrd(): send ip and port error!!!->%s\n", strerror (errno));
            }
            // gettimeofday (&connect_to_server_router_thrd__send_tvEnd, NULL);  // time diff
            // time_diff_connect_to_server_router_thrd__send = time_diff (connect_to_server_router_thrd__send_tvStart, connect_to_server_router_thrd__send_tvEnd);  // time diff
            // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__send,%lf\n", time_diff_connect_to_server_router_thrd__send);  // time diff


            // gettimeofday (&connect_to_server_router_thrd__send_fd_tvStart, NULL);  // time diff
            send_fd (event_fd, sockfd);
            // gettimeofday (&connect_to_server_router_thrd__send_fd_tvEnd, NULL);  // time diff
            // time_diff_connect_to_server_router_thrd__send_fd = time_diff (connect_to_server_router_thrd__send_fd_tvStart, connect_to_server_router_thrd__send_fd_tvEnd);  // time diff
            // fprintf (router_connect_fp, "time_diff_connect_to_server_router_thrd__send_fd,%lf\n", time_diff_connect_to_server_router_thrd__send_fd);  // time diff
#endif

            if (DEBUG)
            {
                printf ("MSG_CONNECT_INVOKE_REQUEST--> send_fd: events[i].data.fd: %d\n", event_fd);
            }
            // close (sockfd);
            close (event_fd);
        }
        close (sockfd);     

        // fflush (router_socket_fp);  // time diff
        // fflush (router_connect_fp);  // time diff
        return NULL;
}


pthread_t create_connect_to_server_router_thrd (connect_to_server_router_thrd_args_t *args)
{
    struct timeval tvStart,tvEnd;
    gettimeofday(&tvStart,NULL);
    pthread_t thread;

    int ret = pthread_create (&thread, NULL, connect_to_server_router_thrd, args);
    assert (ret == 0);

    gettimeofday(&tvEnd,NULL);
    double time_elapsed = time_diff (tvStart,tvEnd);
    if (DEBUG)
    {
        printf ("create_connect_to_server_router_thrd()->comsume time: %f us\n", time_elapsed); 
    }

    return thread;
}


void *uds_server_epoll_event_thrd (void *args)
{

    // printf("enter uds_server_epoll_event_thrd\n");
    // gettimeofday(&create_uds_server_epoll_event_thrd_tvEnd,NULL);  // time diff

    uint32_t len;
    struct sockaddr_un client_sockaddr; 
    struct epoll_event ev;

    int server_sock = ((uds_server_epoll_event_thrd_args_t*) args)->server_sock; 
    int event_fd = ((uds_server_epoll_event_thrd_args_t*) args)->event_fd; 
    int epoll_fd = ((uds_server_epoll_event_thrd_args_t*) args)->epoll_fd; 
    int accept_fd = ((uds_server_epoll_event_thrd_args_t*) args)->accept_fd; 

        if(event_fd == server_sock)
        {

          if (DEBUG)
          {
              printf("uds_server_thrd: accept fd: %d\n", accept_fd);  
          }
          if(accept_fd < 0){
            perror("can't listen client connect request");
            close(server_sock);
          }
 
         ev.data.fd = accept_fd;
         ev.events = EPOLLIN;
 
        if (epoll_ctl(epoll_fd,EPOLL_CTL_ADD,accept_fd,&ev) == -1)
        {
            printf("uds_server_thrd()->epoll_ctl(): EPOLL_CTL_ADD2 error: %s\n", strerror(errno));
        }
       }
       else
       {

        char *recv_buf = (char*) malloc (256);

        // gettimeofday(&uds_server_epoll_event_thrd__recv_tvStart,NULL);  // time diff
        int bytes_rec = recv (event_fd, recv_buf, 20, 0); 
        // gettimeofday(&uds_server_epoll_event_thrd__recv_tvEnd,NULL);  // time diff

        // printf("recv_bytes: %d\n", bytes_rec);

        double uds_server_epoll_event_thrd__recv_tvEnd_us;
    
        uds_server_epoll_event_thrd__recv_tvEnd_us = (double)uds_server_epoll_event_thrd__recv_tvEnd.tv_sec*1000000 + (double)uds_server_epoll_event_thrd__recv_tvEnd.tv_usec;

        // fprintf (router_connect_fp, "uds_server_epoll_event_thrd__recv_tvEnd_us,%lf\n", uds_server_epoll_event_thrd__recv_tvEnd_us);  // time diff

        // if (bytes_rec > 0)  // time diff
        // {  // time diff
            // time_diff_uds_server_epoll_event_thrd__recv = time_diff (uds_server_epoll_event_thrd__recv_tvStart, uds_server_epoll_event_thrd__recv_tvEnd);  // time diff
            // fprintf (router_socket_fp, "time_diff_uds_server_epoll_event_thrd__recv,%lf\n", time_diff_uds_server_epoll_event_thrd__recv);  // time diff

            // time_diff_create_uds_server_epoll_event_thrd = time_diff (create_uds_server_epoll_event_thrd_tvStart, create_uds_server_epoll_event_thrd_tvEnd);  // time diff
            // fprintf (router_socket_fp, "time_diff_create_uds_server_epoll_event_thrd,%lf\n", time_diff_create_uds_server_epoll_event_thrd);  // time diff
        // }  // time diff

        if(bytes_rec <= 0) 
        {            
            // if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event_fd, NULL) != 0)
            // {
            //     // printf("uds_server_epoll_event_thrd() EPOLL_CTL_DEL error: %s\n", strerror (errno));
            // }
            close(event_fd);
            // // // printf("bytes_rec: %d\n", bytes_rec);
            pthread_exit (0);
            // // // printf("remove socket %d from epoll fd %d.\n", events[i].data.fd, epfd);

        }
            connect_to_server_router_thrd_args_t *args = (connect_to_server_router_thrd_args_t*) malloc (sizeof(connect_to_server_router_thrd_args_t));
            args->recv_buf = recv_buf;
            args->event_fd = event_fd;
            args->epoll_fd = epoll_fd;
            
            // create_connect_to_server_router_thrd (args);
            // add_task_2_tpool (connect_to_server_router_tpool, connect_to_server_router_thrd, args);
            connect_to_server_router_thrd (args);

            if (DEBUG)
            {
                printf("uds_server_thrd()->add_task_2_tpool() done.\n");
            }
       }
        // fflush (router_socket_fp);  // time diff
        // fflush (router_connect_fp);  // time diff
    return NULL;
}

pthread_t create_uds_server_epoll_event_thrd (uds_server_epoll_event_thrd_args_t *args)
{
    pthread_t thread;

    int ret = pthread_create (&thread, NULL, uds_server_epoll_event_thrd, args);
    if (ret != 0)
    {
        printf("create_uds_server_epoll_event_thrd error: %s\n", strerror (errno));
    }

    return thread;
}

  
void *uds_server_thrd (void *args)
{

    //create epoll 
    int epfd,eventfd;
    struct epoll_event ev,events[102400];
  
    epfd = epoll_create(102400);


    uint32_t server_sock, client_sock, len, rc;
    uint32_t bytes_rec = 0;
    struct sockaddr_un server_sockaddr;
    struct sockaddr_un client_sockaddr;     
    char buf[256];
    int backlog = 102400;
    memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));
    memset(buf, 0, 256);                

    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock == -1)
    {
        printf("SOCKET ERROR\n");
        exit(1);
    }

  
    ev.data.fd = server_sock;
    ev.events = EPOLLIN;
  
    if (epoll_ctl(epfd,EPOLL_CTL_ADD,server_sock,&ev) == -1)
    {
        printf("uds_server_thrd()->epoll_ctl(): EPOLL_CTL_ADD1 error: %s\n", strerror(errno));
    }
  
    
    server_sockaddr.sun_family = AF_UNIX;   
    strcpy(server_sockaddr.sun_path, UNIX_SOCKET_PATH); 
    len = sizeof(server_sockaddr);
    
    unlink(UNIX_SOCKET_PATH);
    rc = bind(server_sock, (struct sockaddr*) &server_sockaddr, len);
    if (rc == -1){
        printf("BIND ERROR%s\n", strerror(errno));
        close(server_sock);
        exit(1);
    }
    

    rc = listen(server_sock, backlog);
    if (rc == -1){ 
        printf("LISTEN ERROR\n");
        close(server_sock);
        exit(1);
    }
    // // printf("socket listening...\n");
    // int accept_fd;
    msg_t *msg = NULL;
    while (true)
    {
      int nfds = epoll_wait(epfd,events,102400,-1);

      // // printf("uds_server_thrd() nfds: %d\n", nfds);

      for(int i=0;i<nfds;i++)
      {
        // printf("uds_server_thrd()->events[i].data.fd： %d\n", events[i].data.fd);
        if (DEBUG)
        {
            printf("uds_server_thrd()->events[i].data.fd： %d\n", events[i].data.fd);
        }
        int accept_fd; 
        if (events[i].data.fd == server_sock) 
        {
            // gettimeofday(&uds_server_thrd__accept_tvStart,NULL);  // time diff
            accept_fd = accept(server_sock, (struct sockaddr*) &client_sockaddr, &len);  

            if (accept_fd == -1)
            {
                printf("uds_server_thrd() accept() error: %s\n", strerror (errno));
            }
            // gettimeofday(&uds_server_thrd__accept_tvEnd,NULL);  // time diff
            // time_diff_uds_server_thrd__accept = time_diff (uds_server_thrd__accept_tvStart, uds_server_thrd__accept_tvEnd);  // time diff
            // fprintf (router_socket_fp, "time_diff_uds_server_thrd__accept,%lf\n", time_diff_uds_server_thrd__accept);  // time diff
            // fflush (router_socket_fp);  // time diff
            // fflush (router_connect_fp);  // time diff

        }
        else
        {
            // gettimeofday(&epoll_ctl_tvStart,NULL);  // time diff
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL) != 0)
            {
                printf("uds_server_thrd() EPOLL_CTL_DEL error: %s\n", strerror (errno));
            }
            // gettimeofday(&epoll_ctl_tvEnd,NULL);  // time diff
            // time_diff_epoll_ctl = time_diff (epoll_ctl_tvStart, epoll_ctl_tvEnd);  // time diff
            // fprintf (router_socket_fp, "time_diff_epoll_ctl,%lf\n", time_diff_epoll_ctl);  // time diff
            // fflush (router_socket_fp);  // time diff

        }
        // accept_fd = accept4(server_sock, (struct sockaddr*) &client_sockaddr, &len, SOCK_NONBLOCK);

        uds_server_epoll_event_thrd_args_t *args = (uds_server_epoll_event_thrd_args_t *) malloc (sizeof (uds_server_epoll_event_thrd_args_t));
        args->server_sock = server_sock;
        args->event_fd = events[i].data.fd;
        args->epoll_fd = epfd;
        args->accept_fd = accept_fd;

        // gettimeofday(&create_uds_server_epoll_event_thrd_tvStart,NULL);  // time diff
       
        if (USE_THREAD_POOL)
        {
            add_task_2_tpool (uds_server_epoll_event_tpool, uds_server_epoll_event_thrd, args); 
        }
        else
        {
            if (pthread_detach (create_uds_server_epoll_event_thrd (args)) != 0)
            {
                printf("pthread_detach(create_uds_server_epoll_event_thrd) error: %s\n", strerror (errno));
            }
        }
        
        // printf("add task w tpool done\n");
    }
}
}


pthread_t create_uds_server_thrd (hash_table_slot_t *hash_table)
{
    pthread_t thread;

    int ret = pthread_create (&thread, NULL, uds_server_thrd, hash_table);
    assert (ret == 0);

    return thread;
}

pthread_t create_host_tcp_server_thrd (int *port)
{
    pthread_t thread;

    int ret = pthread_create (&thread, NULL, host_tcp_server_thrd, port);
    assert (ret == 0);

    return thread;
}

pthread_t create_host_tcp_server_send_fd_thrd (host_tcp_server_send_fd_thrd_args_t *args)
{
    pthread_t thread;

    int ret = pthread_create (&thread, NULL, host_tcp_server_send_fd_thrd, args);
    assert (ret == 0);

    return thread;
}

void *UDP_proess_unix_msg_thrd2(void *args)
{
    int server_sock = ((tcp_server_epoll_event_thrd_args_t*) args)->server_sock;
    int event_fd = ((tcp_server_epoll_event_thrd_args_t*) args)->event_fd;
    int epoll_fd = ((tcp_server_epoll_event_thrd_args_t*) args)->epoll_fd;
    int accept_fd = ((tcp_server_epoll_event_thrd_args_t*) args)->accept_fd;

    struct epoll_event event;
    struct epoll_event events[102400];
    event.data.fd = accept_fd;
    event.events = EPOLLIN;
    fcntl(accept_fd, F_SETFL, fcntl(accept_fd, F_GETFL) | O_NONBLOCK);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accept_fd, &event) == -1) {
        perror("[UDP_proess_unix_msg_thrd2] epoll_ctl error");
        exit(EXIT_FAILURE);
    }
    if (debug_flag){
        printf("size %ld\n", sizeof(hash_msg));
        printf("Process client message\n");
        printf("server_sock  %d event_fd  %d  epoll_fd  %d  accept_fd   %d  \n", 
                    server_sock, event_fd, epoll_fd, accept_fd);
    }
    
    while (1){ 
        int nfds = epoll_wait(epoll_fd, events, 102400, -1);
        if (debug_flag)
            printf("Epoll_wait is triggered(accept_fd)\n");
        for ( int i=0; i<nfds; i++)
        {
            if ( events[i].data.fd == accept_fd ) 
            {
                if (debug_flag)
                    printf("Iterate to the contanier fd\n");
                // char buffer[32];
                hash_msg * msg = (hash_msg *)malloc(sizeof(hash_msg));
                char send_buf_t[32];
                memset(send_buf_t, 0, sizeof(send_buf_t));
                // memset(buffer, 0, sizeof(buffer));
                int recv_ret = read (accept_fd, msg, sizeof(hash_msg));
                // hash_msg *msg = (hash_msg *) buffer;
                if ( msg->req_type==MSG_SOCKET_INVOKE_REQUEST )
                {
                    fflush(stdout);
                    if (debug_flag)
                        printf("==================================MSG_SOCKET_INVOKE_REQUEST=========================\n");
                    int host_fd = socket(AF_INET, SOCK_DGRAM, 0);
                    send_fd(accept_fd, host_fd);
                    if (debug_flag)
                        printf("Create host_fd %d", host_fd);
                }
                else if ( msg->req_type==MSG_BIND_INVOKE_REQUEST ){ 
                    // fflush(stdout);
                    if (debug_flag)
                        printf("==================================MSG_BIND_INVOKE_REQUEST=========================\n");
                    int host_fd = recv_fd(accept_fd);
                    if (debug_flag)
                        printf("recv host_fd %d\n", host_fd);
                    struct sockaddr_in host_addr; //host_addr
                    int unused_port = 0;
                    memset(&host_addr, 0, sizeof(host_addr));

                    host_addr.sin_family = AF_INET; 
                    host_addr.sin_addr.s_addr = INADDR_ANY; 
                    host_addr.sin_port = htons(unused_port);
                    socklen_t host_addr_len;
                    host_addr_len = sizeof(host_addr);
                    int host_ret = bind(host_fd, (struct sockaddr *)&host_addr, host_addr_len);
                    if (getsockname(host_fd, (struct sockaddr *)&host_addr, &host_addr_len) < 0) 
                    {
                        fprintf(stderr, "ERROR! Faild to retrive port number\n");
                    }
                    send_fd(accept_fd, host_fd);
                }
                else if ( msg->req_type==MSG_INSERT_INVOKE_REQUEST ){
                    if (debug_flag)
                        printf("==================================MSG_INSERT_INVOKE_REQUEST=========================\n");
                    pthread_mutex_lock(&listen_server_host_table_mutex);
                    hash_table_insert(listen_server_host_info, msg->hash_key, 0, msg->m_port);
                    pthread_mutex_unlock(&listen_server_host_table_mutex);
                }
                else if ( msg->req_type==MSG_SEARCH_HOST_ADDR_INVOKE_REQUEST){
                    if (debug_flag)
                        printf("==================================MSG_SEARCH_HOST_ADDR_INVOKE_REQUEST=========================\n");
                    ip_mapping_link_list_node_t *node = ip_mapping_hash_table_search_viaip (ip_mapping_hash_table, msg->m_addr);
                    if (node == NULL)
                    {
                        perror("ip_mapping_hash_table_search_viaip error!\n");
                    }
                    msg->m_addr = node->mapping_info->host_ip;
                    memcpy (send_buf_t, msg, sizeof (hash_msg));
                    int send_ret = send (accept_fd, send_buf_t, sizeof(hash_msg), 0);
                    if (send_ret == -1)
                    {
                       perror("unix_sock send error!\n");
                    }
                }else if ( msg->req_type==MSG_SEARCH_CLIENT_INVOKE_REQUEST){
                    uint64_t client_hash = msg->hash_key;
                    hash_node_t *client_node = hash_table_search(client_host_info, client_hash);
                    if ( client_node==NULL )
                    {
                        perror("[thread_func2] ERROR! CLIENT NODE IS NULL!");
                        close(accept_fd);
                        return NULL;
                    }
                    msg->m_addr = client_node->m_addr;
                    msg->m_port = client_node->m_port;

                    memcpy (send_buf_t, msg, sizeof (hash_msg));
                    int send_ret = send (accept_fd, send_buf_t, sizeof(hash_msg), 0);
                    if (send_ret == -1)
                    {
                       perror("unix_sock send error!\n");
                    }
                }
                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, accept_fd, NULL) != 0)
                {
                    printf("uds_server_thrd() EPOLL_CTL_DEL error: %s\n", strerror (errno));
                }
                close(accept_fd); 
                return NULL;
            }
        }
    }
}   

void *UDP_process_pkt_fw_thrd(void *args)
{
    if ( debug_flag )
        printf("==================================[UDP_process_pkt_fw_thrd]===========================================\n");
    udp_listen_router_epoll_event_thrd_args_t *args_t = (udp_listen_router_epoll_event_thrd_args_t *)args;
    int listening_socket = args_t->listening_socket;
    char *buf = args_t->buf;
    size_t n = args_t->n;
    int  flags = args_t->flags;
    struct sockaddr_in * sin = (struct sockaddr_in *)args_t->addr;
    socklen_t   addr_len = args_t->addr_len;

    uint64_t hash_key = GetHashViaPacket(buf);
    
    hash_node_t *server_node = hash_table_search(listen_server_host_info, hash_key);
    // struct sockaddr_in *sin = addr;
    uint64_t client_hash = GetHash(ntohl ((sin->sin_addr).s_addr), ntohs (sin->sin_port));
    hash_node_t *host_node = hash_table_search(client_host_info, client_hash);
    if ( host_node==NULL ) 
    {
        pthread_mutex_lock(&client_host_table_mutex);
        hash_table_insert(client_host_info, client_hash, ntohl ((sin->sin_addr).s_addr), ntohs (sin->sin_port));
        pthread_mutex_unlock(&client_host_table_mutex);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_node->m_port);
    server_addr.sin_addr.s_addr = htonl(server_node->m_addr);
    // sendto(listening_socket, msg, strlen(msg), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    int routersend_ret = RouterSend(listening_socket, buf, strlen(buf), flags, (struct sockaddr*)&server_addr, sizeof(server_addr), client_hash);
    return NULL;
}

void *UDP_router_unix(void *args)
{
    printf("==================================[host_router_unix_thrd]===========================================\n");
    int udp_unix_num = 30;
    tpool_t *UDP_proess_msg_epoll_pool = NULL;
    create_tpool (&UDP_proess_msg_epoll_pool, udp_unix_num);
    umask(0);
    int server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, SOCKET_FILE);
    if ( access(SOCKET_FILE, F_OK)==0 )
    {
        if ( unlink(SOCKET_FILE)==-1 )
        {
            perror("UNLINK ERROR!\n");
            close(server_sockfd);
            return NULL;
        }
    }

    if ( bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1 )
    {
        perror("BIND ERROR!");
        close(server_sockfd);
        return NULL;
    }
    if ( listen(server_sockfd, 100)==-1 ){
        perror("LISTEN ERROR!");
        close(server_sockfd);
        return NULL;
    }

    char buffer[256];
    char send_buf_t[256];
    if (debug_flag)
        printf("listening router unix process communication\n");
    int epoll_fd = epoll_create1(0);
    struct epoll_event event;
    struct epoll_event events[102400];
    event.events = EPOLLIN;
    event.data.fd = server_sockfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sockfd, &event) == -1) {
        perror("[UDP_router_unix] epoll_ctl error");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        int nfds = epoll_wait(epoll_fd, events, 102400, -1);
        if (debug_flag)
            printf("Epoll_wait is triggered(server_sock)\n");
        for ( int i=0; i<nfds; i++)
        {
            if ( events[i].data.fd == server_sockfd ) 
            {
                if (debug_flag)
                    printf("Iterate to the server_sockfd\n");
                int UDPcontanier_fd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
                event.data.fd = UDPcontanier_fd;

                udp_router_epoll_event_thrd_args_t *args_t = (udp_router_epoll_event_thrd_args_t *) malloc (sizeof (udp_router_epoll_event_thrd_args_t));
                args_t->server_sock = server_sockfd;
                args_t->event_fd = events[i].data.fd;
                args_t->epoll_fd = epoll_fd;
                args_t->accept_fd  = UDPcontanier_fd;
                if (debug_flag)
                    printf("server_sock  %d event_fd  %d  epoll_fd  %d  accept_fd   %d  \n", 
                        args_t->server_sock, args_t->event_fd, args_t->epoll_fd, args_t->accept_fd);
                add_task_2_tpool(UDP_proess_msg_epoll_pool, UDP_proess_unix_msg_thrd2, (void *)args_t);
            }
        }  
    }
    return NULL;
}

void *UDP_listen_thrd(void *)
{
    printf("==================================[UDP_listen_thrd]===========================================\n");
    int udp_listen_num = 30;
    tpool_t *UDP_process_pkt_fw_pool = NULL;
    create_tpool (&UDP_process_pkt_fw_pool, udp_listen_num);

    struct sockaddr_in listening_addr; //listening_addr
    int listening_socket = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&listening_addr, 0, sizeof(listening_addr));

    listening_addr.sin_family = AF_INET; 
    listening_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listening_addr.sin_port = htons(LISTEN_PORT);
    socklen_t listening_addr_len;
    listening_addr_len = sizeof(listening_addr);
    fd_table[listening_socket] = LISTEN_FD;
    int optval = 1;
    if (setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        return NULL;
    }
    int listening_ret = bind(listening_socket, (struct sockaddr *)&listening_addr, listening_addr_len);
    if (listening_ret < 0) {
        perror("listening server bind error");
        return NULL;
    }

    if (debug_flag)
        printf("UDP listen server ip:%s, port:%hu\n",
            inet_ntoa(listening_addr.sin_addr), htons(listening_addr.sin_port)
            );

    char msg[1470];
    int epoll_fd = epoll_create1(0);
    struct epoll_event event;
    struct epoll_event events[100];
    event.events = EPOLLIN;
    event.data.fd = listening_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listening_socket, &event) == -1) {
        perror("[UDP_listen_thrd] epoll_ctl error");
        exit(EXIT_FAILURE);
    }
    while( 1 ){
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int nfds = epoll_wait(epoll_fd, events, 100, -1);
        if (debug_flag)
            printf("Epoll_wait is triggered(listen_sock)\n");
        for ( int i=0; i<nfds; i++)
        {
            if ( events[i].data.fd == listening_socket ) 
            {
                if (debug_flag)
                    printf("===================================[UDP_router_sendto_thrd]=======================================\n");
                ssize_t s = recvfrom(listening_socket, msg, sizeof(msg)-1, 0, (struct sockaddr*)&addr,&len);
                udp_listen_router_epoll_event_thrd_args_t *args_t = (udp_listen_router_epoll_event_thrd_args_t *) malloc (sizeof (udp_listen_router_epoll_event_thrd_args_t));
                args_t->listening_socket = listening_socket;
                args_t->buf = msg;
                args_t->n = s;
                args_t->flags = 0;
                args_t->addr = (struct sockaddr *)&addr;
                args_t->addr_len = len;
                add_task_2_tpool(UDP_process_pkt_fw_pool, UDP_process_pkt_fw_thrd, (void *)args_t);
            }
        }
    }
}

int main ()
{
    // router_socket_fp = fopen("router-socket-benchmark.csv", "a+");  // time diff
    // router_connect_fp = fopen("router-connect-benchmark.csv", "a+");  // time diff

    srand((unsigned)time(NULL)); 
    hash_table_init (hash_table, HASHSIZE);
    init_ip_mapping_hash_table (ip_mapping_hash_table);
    if ( USE_TCP_MODE )
    {
        hash_table_init (hash_table, HASHSIZE);
        init_ip_mapping_hash_table (ip_mapping_hash_table);
        if(0 != create_tpool (&tcp_server_epoll_event_tpool, tcp_server_epoll_event_tpool_tnumber))
        {
            printf("create_tpool: tcp_server_epoll_event_tpool failed!\n");
            return -1;
        }

        if(0 != create_tpool (&uds_server_epoll_event_tpool, uds_server_epoll_event_tpool_tnumber))
        {
            printf("create_tpool: uds_server_epoll_event_tpool failed!\n");
            return -1;
        }

        pthread_t tcp_server_thrd_id_arr[10];

        pthread_t uds_server_thrd_id = create_uds_server_thrd ((hash_table_slot_t*)hash_table);
        for (int i = 0; i < listen_thrd_num; i++)
        {
            int *port = (int*) malloc (sizeof(int));
            *port = listenfd_arr[i];
            tcp_server_thrd_id_arr[i] = create_host_tcp_server_thrd (port);
            // printf("SlimFastRouter Listening %d\t", *port);
        }
        // printf("\n");
        pthread_join (uds_server_thrd_id, NULL);

        for (int i =0; i < listen_thrd_num; i++)
        {
            pthread_join (tcp_server_thrd_id_arr[0], NULL);
        }
    }
    else
    {
        client_host_info = create_hash_table(); 
        listen_server_host_info = create_hash_table(); 
        printf("HOST INTERFACES\n");
        print_interface_addresses();

        pthread_t thread1, thread2; 
        pthread_create(&thread1, NULL, UDP_listen_thrd, NULL);
        pthread_create(&thread2, NULL, UDP_router_unix, NULL);

        // pthread_detach(thread1);
        // pthread_detach(thread2);
        pthread_join(thread1, NULL);
        pthread_join(thread2, NULL);
        // UDP_router_unix();

    }
    
    return 0;
}
