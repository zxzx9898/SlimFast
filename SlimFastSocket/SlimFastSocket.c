#define _GNU_SOURCE

// #define SECURITY

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <dlfcn.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pthread.h> 

#include <string.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include "HashTable.h"
#define MAXLINE 9999


#define UNIX_SOCKET_PATH "/SlimFast/SlimFastRouter/SlimFastRouter"
#define MSG_SOCKET_INVOKE_REQUEST   0
#define MSG_BIND_INVOKE_REQUEST     1
#define MSG_LISTEN_INVOKE_REQUEST   2
#define MSG_CONNECT_INVOKE_REQUEST  3
#define MSG_ACCEPT_INVOKE_REQUEST   4
#define MSG_ACCEPT4_INVOKE_REQUEST  5
#define MSG_INSERT_INVOKE_REQUEST   6
#define MSG_SEARCH_HOST_ADDR_INVOKE_REQUEST   7
#define MSG_SEARCH_CLIENT_INVOKE_REQUEST   8


#define DEBUG false
#define debug_flag false
int test_mod_sendto = 0;
int test_mod_recvfrom = 0;
bool test_hash_overhead = 1;
int counter_round = 0;

#define LISTEN_FD 1
#define SERVER_FD 2
#define CLIENT_FD 3
#define LISTEN_PORT 9999

#define SOCKET_FILE "/SlimFast/SlimFastRouter/SlimFastUDPRouter"

uint8_t fd_table[65536] = {0}; 
uint64_t fd_to_hash_table[65536] = {0}; 
bool Hash_listen = false;
hash_table_t *client_host_info; 
hash_table_t *listen_server_host_info; 
hash_table_t *server_host_info;  
hash_table_t *server_host_table; 
hash_table_t *client_need_hash_table; 

// static uint32_t port_uds_mapping_arr[65535]; 
int counter;

int fd_to_epoll_fd[65536];
struct epoll_event epoll_events[65536];

typedef struct socket_info 
{
    uint8_t     req_type;
    uint64_t    hash_key;
    uint32_t    m_addr;
    uint16_t    m_port;
}hash_msg;

typedef struct epoll_fd_arr_s
{
    int epoll_fd_num;
    int epoll_fd_arr[100];
}epoll_fd_arr_t;

typedef struct security_mode_host_fd_s
{
    int host_fd;
}security_mode_host_fd_t;

epoll_fd_arr_t epoll_fd_arr;

pthread_mutex_t epoll_fd_arr_mutex;


double time_diff(struct timeval x , struct timeval y)
{
    double x_us , y_us , diff;
    
    x_us = (double)x.tv_sec*1000000 + (double)x.tv_usec;
    y_us = (double)y.tv_sec*1000000 + (double)y.tv_usec;
    
    diff = (double)y_us - (double)x_us;

    if(diff<0)
    {
        fprintf(stderr, "ERROR! time_diff<0\n");
        fflush(stdout);
        exit(1);
    }

    // // printf("time_diff: %f\n",diff);
    
    return diff;
}

struct socket_calls { 
    int (*socket)(int domain, int type, int protocol);
    int (*bind)(int socket, const struct sockaddr *addr, socklen_t addrlen);
    int (*listen)(int socket, int backlog);
    int (*accept)(int socket, struct sockaddr *addr, socklen_t *addrlen);
    int (*accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    int (*connect)(int socket, const struct sockaddr *addr, socklen_t addrlen);
    int (*getpeername)(int socket, struct sockaddr *addr, socklen_t *addrlen);
    int (*getsockname)(int socket, struct sockaddr *addr, socklen_t *addrlen);
    int (*setsockopt)(int socket, int level, int optname,
              const void *optval, socklen_t optlen);
    int (*getsockopt)(int socket, int level, int optname,
              void *optval, socklen_t *optlen);
    int (*fcntl)(int socket, int cmd, ... /* arg */);
    int (*close)(int socket);

    ssize_t (*sendto)(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len);
    ssize_t (*recvfrom)(int fd, void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t *addr_len);  

    ssize_t (*recv)(int sockfd, void *buf, size_t len, int flags);
};

struct epoll_calls {
    int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event);
    int (*epoll_create) (int size);
    int (*epoll_create1) (int flags);
};

static struct socket_calls real_socket;
static struct epoll_calls real_epoll;
bool init_preload_has_done = false;


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
            if ((ip >> 24) == 10 ||
                ((ip >> 24) == 172 && (ip >> 16 & 0xff) >= 16 && (ip >> 16 & 0xff) <= 31) ||
                ((ip >> 24) == 192 && (ip >> 16 & 0xff) == 168)) {
                printf("%s: %s\n", ifa->ifa_name, ip_addr);
            }
        }
    }

    freeifaddrs(ifaddr);
}

static void init_preload(void) 
{
    real_socket.socket = dlsym(RTLD_NEXT, "socket");
    real_socket.bind = dlsym(RTLD_NEXT, "bind");
    real_socket.listen = dlsym(RTLD_NEXT, "listen");
    real_socket.accept = dlsym(RTLD_NEXT, "accept");
    real_socket.accept4 = dlsym(RTLD_NEXT, "accept4");
    real_socket.connect = dlsym(RTLD_NEXT, "connect");
    real_socket.getpeername = dlsym(RTLD_NEXT, "getpeername");
    real_socket.getsockname = dlsym(RTLD_NEXT, "getsockname");
    real_socket.setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    real_socket.getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    real_socket.fcntl = dlsym(RTLD_NEXT, "fcntl");
    real_socket.close = dlsym(RTLD_NEXT, "close");
    real_socket.recv = dlsym(RTLD_NEXT, "recv");

    real_socket.sendto = dlsym(RTLD_NEXT, "sendto");
    real_socket.recvfrom = dlsym(RTLD_NEXT, "recvfrom");

    real_epoll.epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
    real_epoll.epoll_create = dlsym(RTLD_NEXT, "epoll_create");
    real_epoll.epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");

    client_host_info = create_hash_table(); 
    listen_server_host_info = create_hash_table(); 
    server_host_info = create_hash_table(); 
    server_host_table = create_hash_table();
    client_need_hash_table = create_hash_table();

    // printf("CONTANIER INTERFACES\n");
    // print_interface_addresses();

    init_preload_has_done = true;
}

static int SlimFast_epoll_fd = -1;
struct epoll_event *SlimFast_epoll_event = NULL;

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
        
        if (op == EPOLL_CTL_ADD)
        {
            // printf("call epoll_ctl: EPOLL_CTL_ADD .........\n");
            fd_to_epoll_fd[fd] = epfd;
            epoll_events[fd] = *event;
        }
        if (op == EPOLL_CTL_DEL)
        {
            fd_to_epoll_fd[fd] = 0;
            // printf("call epoll_ctl: EPOLL_CTL_DEL .........\n");
        }

    return real_epoll.epoll_ctl(epfd, op, fd, event);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    if (DEBUG)
    {
        // printf("recv sockfd: %d\n", sockfd);
    }

    return real_socket.recv (sockfd, buf, len, flags);
}

int epoll_create (int size)
{

    if (init_preload_has_done == false)
    {
        // printf("epoll_create() call --> init_preload ()\n");
        init_preload ();
    }
    // printf("call epoll_create......\n");

    SlimFast_epoll_fd = real_epoll.epoll_create (size);

    if (pthread_mutex_lock(&epoll_fd_arr_mutex) != 0)
    {
        printf("lock error! %s\n", strerror (errno));
    }

    int index = epoll_fd_arr.epoll_fd_num;
    epoll_fd_arr.epoll_fd_arr[index] = SlimFast_epoll_fd;

    epoll_fd_arr.epoll_fd_num ++;
    pthread_mutex_unlock(&epoll_fd_arr_mutex);

    return SlimFast_epoll_fd;
}

int epoll_create1 (int flags)
{

    if (init_preload_has_done == false)
    {
        // printf("epoll_create1() call --> init_preload ()\n");
        init_preload ();
    }
    // printf("call epoll_create1......\n");

    SlimFast_epoll_fd = real_epoll.epoll_create1 (flags);

    if (pthread_mutex_lock(&epoll_fd_arr_mutex) != 0)
    {
        printf("lock error! %s\n", strerror (errno));
    }

    int index = epoll_fd_arr.epoll_fd_num;
    epoll_fd_arr.epoll_fd_arr[index] = SlimFast_epoll_fd;

    epoll_fd_arr.epoll_fd_num ++;
    pthread_mutex_unlock(&epoll_fd_arr_mutex);

    // printf("call epoll_create1 done\n");

    return SlimFast_epoll_fd;
}

typedef struct msg_s
{
    uint16_t msg_type;
    uint32_t listening_addr;
    uint16_t listening_port;
    uint32_t unix_sock;
    uint32_t fd_number;
}msg_t;

// socket
struct timeval socket_socket_tvStart, socket_socket_tvEnd;
struct timeval socket_init_preload_tvStart, socket_init_preload_tvEnd;
struct timeval socket_connect_router_tvStart, socket_connect_router_tvEnd;
struct timeval socket_send_tvStart, socket_send_tvEnd;
struct timeval socket_recv_fd_tvStart, socket_recv_fd_tvEnd;

struct timeval socket_real_socket_tvStart, socket_real_socket_tvEnd;

double time_diff_socket_socket;
double time_diff_socket_init_preload;
double time_diff_socket_connect_router;
double time_diff_socket_send;
double time_diff_socket_recv_fd;

double time_diff_socket_real_socket;

FILE *socket_fp;


// connect
struct timeval connect_connect_tvStart, connect_connect_tvEnd;
struct timeval connect_connect_router_tvStart, connect_connect_router_tvEnd;
struct timeval connect_send_tvStart, connect_send_tvEnd;
struct timeval connect_send_fd_tvStart, connect_send_fd_tvEnd;
struct timeval connect_recv_fd_tvStart, connect_recv_fd_tvEnd;
struct timeval connect_dup2_tvStart, connect_dup2_tvEnd;

struct timeval connect_add_del_epoll_tvStart, connect_add_del_epoll_tvEnd;

double time_diff_connect_connect;
double time_diff_connect_connect_router;
double time_diff_connect_send;
double time_diff_connect_send_fd;
double time_diff_connect_recv_fd;
double time_diff_connect_dup2;

double time_diff_connect_add_del_epoll;

FILE *connect_fp;

// recv_fd
struct timeval recv_fd__before_recvmsg_tvStart, recv_fd__before_recvmsg_tvEnd;
struct timeval recv_fd__recvmsg_tvStart, recv_fd__recvmsg_tvEnd;
struct timeval recv_fd__after_recvmsg_tvStart, recv_fd__after_recvmsg_tvEnd;

double time_diff_recv_fd__before_recvmsg;
double time_diff_recv_fd__recvmsg;
double time_diff_recv_fd__after_recvmsg;


int recv_fd(int unix_sock)
{
    // gettimeofday(&recv_fd__before_recvmsg_tvStart,NULL);  // time diff
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
    // gettimeofday(&recv_fd__before_recvmsg_tvEnd,NULL);  // time diff

    // gettimeofday(&recv_fd__recvmsg_tvStart,NULL);  // time diff
    size = recvmsg (unix_sock, &msg, 0);
    // gettimeofday(&recv_fd__recvmsg_tvEnd,NULL);  // time diff

    // gettimeofday(&recv_fd__after_recvmsg_tvStart,NULL);  // time diff
    if (DEBUG)
    {
        // printf("recv_fd recv bytes: %d\n", size);
    }

    if (size < 0) {
        printf ("recvmsg error: %s\n", strerror (errno));
        exit(EXIT_FAILURE);
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmsg->cmsg_level != SOL_SOCKET) {
            fprintf (stderr, "invalid cmsg_level %d\n",
                    cmsg->cmsg_level);
            return -1;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) {
            fprintf (stderr, "invalid cmsg_type %d\n",
                    cmsg->cmsg_type);
            return -1;
        }
        int *fd_p = (int *)CMSG_DATA(cmsg);
        fd = *fd_p;
        // // printf ("received fd %d\n", fd);
    } else {
        fd = -1;
    }
    if ( debug_flag )
    printf ("socket received fd %d\n", fd);
    // gettimeofday(&recv_fd__after_recvmsg_tvEnd,NULL);  // time diff

    return(fd);
}

int send_fd(int sock, int fd)
{
    if (DEBUG)
    {
        printf("socket start send fd %d\n", fd);
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

        //// printf ("passing fd %d\n", fd);
        *((int *) CMSG_DATA(cmsg)) = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        //// printf ("not passing fd\n");
    }

    size = sendmsg(sock, &msg, 0);

    if (size < 0) {
        perror ("sendmsg");
    }

    if (DEBUG)
    {
        // printf("send_fd(): send fd end!!!\n");
    }
    return size;
}

int connect_router() {
    if (DEBUG) {
        // printf("connect router...\n");
        fflush(stdout);
    }
    int unix_sock = real_socket.socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_sock < 0) {
        printf("Cannot create unix socket.\n");
        return -1;
    }
    struct sockaddr_un saun;
    memset(&saun, 0, sizeof(saun));
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, UNIX_SOCKET_PATH);
    int len = sizeof(saun.sun_family) + strlen(saun.sun_path);
    if (real_socket.connect(unix_sock, (struct sockaddr*)&saun, len) < 0) {
        printf("Cannot connect router. try again\n");
        real_socket.close(unix_sock);
    }
    return unix_sock;
}


int connect_UDProuter(){
    if (debug_flag) {
        printf("connect UDProuter...\n");
        fflush(stdout);
    }
    int unix_sock = real_socket.socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_sock < 0) {
        printf("Cannot create unix socket.\n");
        return -1;
    }
    struct sockaddr_un saun;
    memset(&saun, 0, sizeof(saun));
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, SOCKET_FILE);
    if (real_socket.connect(unix_sock, (struct sockaddr*)&saun, sizeof(saun)) < 0) {
        printf("Cannot connect router. try again\n");
        real_socket.close(unix_sock);
    }
    return unix_sock;    
}

uint64_t GetHash2(uint32_t ip, uint16_t port)
{
    uint64_t key;
    uint64_t ip_uint64;
    uint64_t ip_left_shift_16;

    ip_uint64 = ip;
    ip_left_shift_16 = ip_uint64 << 16;
    key = ip_left_shift_16 ^ port;

    return key;
}

int socket (int domain, int type, int protocol)
{
    // gettimeofday(&socket_socket_tvStart,NULL);  // time diff
    if (init_preload_has_done == false)
    {
        init_preload ();
    }

    if ((domain == AF_INET || domain == AF_INET6) && (type & SOCK_DGRAM) && (!protocol || protocol == IPPROTO_UDP)) {
        counter_round++;
        if ( counter_round==507 )
            // debug_flag = true;
        if (debug_flag)
        {
            printf("udp socket\n");
        }
        int host_fd = real_socket.socket(domain, type, protocol);
        int host_fd_t;
        int unix_sock = connect_UDProuter();
        if ( unix_sock<0 )
        {
            perror("unix socket() error!\n");
        }
        char send_buf_t[256];
        // char recv_buf_t[256];
        hash_msg *msg = (hash_msg *)malloc(sizeof(hash_msg));;
        msg->req_type = MSG_SOCKET_INVOKE_REQUEST;
        msg->hash_key = 0;
        msg->m_addr = 0;
        msg->m_port = 0;
        memcpy (send_buf_t, msg, sizeof (hash_msg));
        // int send_ret = send (unix_sock, send_buf_t, sizeof(hash_msg), 0);
        int send_ret = write (unix_sock, send_buf_t, sizeof(hash_msg));
        if ( send_ret == -1 )
        {
           perror("unix_sock send error!\n");
        }
        else
        {
            if ( debug_flag )
                printf("send_ret %d\n", send_ret);
        }
        host_fd_t = recv_fd(unix_sock);
        if ( debug_flag )
            printf("[SOCKET   1] host_fd %d  host_fd_t %d\n", 
                    host_fd, host_fd_t);
        if ( debug_flag )
        {
            struct sockaddr_in host_addr_t;
            socklen_t host_addr_len_t;
            host_addr_len_t = sizeof(host_addr_t);
            getsockname(host_fd, (struct sockaddr *)&host_addr_t, &host_addr_len_t);
            struct sockaddr_in host_addr_t2;
            socklen_t host_addr_len_t2;
            host_addr_len_t2 = sizeof(host_addr_t2);
            getsockname(host_fd_t, (struct sockaddr *)&host_addr_t2, &host_addr_len_t2);
        }
        

        dup2(host_fd_t, host_fd); 
        if ( debug_flag )
            printf("[SOCKET   2] host_fd %d  host_fd_t %d\n", 
                    host_fd, host_fd_t);
        close(host_fd_t);
        if ( debug_flag )
            printf("[SOCKET   ] host_fd %d\n", 
                    host_fd);
        // free(msg);
        real_socket.close(unix_sock);
        fd_table[host_fd] = CLIENT_FD; 
        return host_fd;
    }
    return 0;
}

int SendListenServerInfo(hash_msg *msg)
{
    int unix_socket = connect_UDProuter();
    char send_buf_t[256];
    memcpy (send_buf_t, msg, sizeof (hash_msg));
    // int send_ret = send (unix_socket, send_buf_t, sizeof(hash_msg), 0);
    int send_ret = write (unix_socket, send_buf_t, sizeof(hash_msg));
    if ( send_ret == -1 )
    {
       printf("unix_sock send error!\n");
    }
    // free(msg);
    memset(send_buf_t, 0, sizeof(send_buf_t));
    real_socket.close(unix_socket);

    return 0;
}

uint16_t GetHostPort(int sockfd)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int ret = getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
    if (ret == -1) {
        perror("getsockname");
        return 0;
    }
    if (debug_flag) 
        printf("[GetHostPort]sockfd %d host_ip %s host_port %d\n", 
            sockfd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return ntohs(addr.sin_port);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if ( fd_table[sockfd] == CLIENT_FD)
    {
        int unix_sock = connect_UDProuter();
        if ( unix_sock<0 )
        {
            perror("unix socket() error!\n");
        }
        // char send_buf_t[256];
        hash_msg *msg = (hash_msg *)malloc(sizeof(hash_msg));;
        msg->req_type = MSG_BIND_INVOKE_REQUEST;
        msg->hash_key = 0;
        msg->m_addr = 0;
        msg->m_port = 0;

        int send_ret = write (unix_sock, msg, sizeof(hash_msg));
        if ( send_ret == -1 )
        {
           perror("unix_sock send error!\n");
        }
        else
        {
            if (debug_flag) 
                printf("send_ret %d\n", send_ret);
        }

        if ( send_fd(unix_sock, sockfd)<0 )
        {
            perror("[BIND] send fd failed!\n");
            return 0;
        }
        else
        {
            if (debug_flag) 
                printf("send fd success!host_fd %d \n", sockfd);
        }

        int bind_sockfd = recv_fd(unix_sock); 
        if (debug_flag) 
            printf("[BIND   ] bind_sockfd %d  sockfd  %d \n", 
                    bind_sockfd, sockfd);
        real_socket.close(unix_sock);
        if ( dup2(bind_sockfd, sockfd)==-1 )
        {
            perror("dup2() error!\n");
            return 0;
        }
        close(bind_sockfd); 
        fd_table[sockfd] = SERVER_FD; 

        msg = (hash_msg *)malloc(sizeof(hash_msg)); 
        uint32_t contanier_ip = ntohl (((struct sockaddr_in*)addr)->sin_addr.s_addr);
        uint16_t contanier_port = ntohs (((struct sockaddr_in*)addr)->sin_port);
        uint16_t host_port = GetHostPort(sockfd);
        uint64_t hash = 0;
        if ( contanier_ip==0 ) 
        {
            if (debug_flag) 
                printf("Traverse the NIC device\n");
            struct ifaddrs *ifaddr, *ifa;
            char ip_addr[INET_ADDRSTRLEN];
            if (getifaddrs(&ifaddr) == -1) {
                perror("getifaddrs");
                return 0;
            }

            for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
            {
                if (ifa->ifa_addr == NULL) {
                    continue;
                }
                if (ifa->ifa_addr->sa_family == AF_INET)
                {
                    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                    uint32_t contanier_ip_t = ntohl(addr->sin_addr.s_addr);
                    inet_ntop(AF_INET, &addr->sin_addr, ip_addr, INET_ADDRSTRLEN);
                    if ((contanier_ip_t >> 24) == 10 ||
                        ((contanier_ip_t >> 24) == 172 && (contanier_ip_t >> 16 & 0xff) >= 16 && (contanier_ip_t >> 16 & 0xff) <= 31) ||
                        ((contanier_ip_t >> 24) == 192 && (contanier_ip_t >> 16 & 0xff) == 168))
                    {
                        if (debug_flag) 
                            printf("%s: %s\n", ifa->ifa_name, ip_addr);
                        hash = GetHash2(contanier_ip_t, contanier_port);
                        fd_to_hash_table[sockfd] = hash;
                        msg->req_type = MSG_INSERT_INVOKE_REQUEST;
                        msg->hash_key = hash; 
                        msg->m_addr = 0;
                        msg->m_port = host_port;
                        SendListenServerInfo(msg);
                    }
                }
            }
        }
        else
        {
            hash = GetHash2(contanier_ip, contanier_port); 
            fd_to_hash_table[sockfd] = hash;
            msg->req_type = MSG_INSERT_INVOKE_REQUEST;
            msg->hash_key = hash;
            msg->m_addr = 0;
            msg->m_port = host_port;
            SendListenServerInfo(msg);
        }
        
        free(msg);
        return 0;
    }
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	uint32_t listening_addr = 0;
	uint16_t listening_port;
	uint32_t unix_socket;

	char send_buf[50] = {0};

	listening_addr = ntohl ((sin->sin_addr).s_addr);
	listening_port = ntohs (sin->sin_port);

    unix_socket = connect_router ();

    if (fd_to_epoll_fd[sockfd] > 0)
    {
        if (real_epoll.epoll_ctl (fd_to_epoll_fd[sockfd], EPOLL_CTL_DEL, sockfd, NULL) == -1)
        {
            printf("bind() epoll_ctl EPOLL_CTL_DEL error! %s\n", strerror (errno));
        }
        close (sockfd);

        int ret = dup2 (unix_socket, sockfd); 

        if (ret == -1)
        {
            printf("bind() dup2() error!\n");
        }

        close (unix_socket);

        if (real_epoll.epoll_ctl (fd_to_epoll_fd[sockfd], EPOLL_CTL_ADD, sockfd, &epoll_events[sockfd]) == -1)
        {
            printf("bind()->real_epoll.epoll_ctl()->EPOLL_CTL_ADD error: %s\n", strerror(errno));
        }

        printf("epoll add\n");

    }
    else
    {
        int ret = dup2 (unix_socket, sockfd);

        if (ret == -1)
        {
            printf("bind() dup2() error!\n");
        } 
    }

    if (DEBUG)
    {
        // printf("bind addr: %d, port: %d\n", listening_addr, listening_port);
    }

    if (listening_port == 0)
    {
        return 0;
    }

	msg_t msg;
	msg.msg_type = MSG_BIND_INVOKE_REQUEST;
	msg.listening_addr = listening_addr;
	msg.listening_port = listening_port;
	msg.unix_sock = sockfd;

	memcpy (send_buf, &msg, sizeof (msg_t));

    int ret = send (sockfd, send_buf, sizeof (msg_t), 0);
    if (ret == -1)
    {
    	printf("unix_sock send error!\n");
    }

    return 0;
}

int listen(int sockfd, int backlog) 
{
    if (DEBUG)
    {
	   // printf("Server psuedo-listen in socket %d\n", sockfd);
    }

    return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    // counter ++;
    // printf("call connect: %d\n", counter);
    // connect_fp = fopen("client-connect-benchmark.csv", "a+");  // time diff
    // gettimeofday(&connect_connect_tvStart,NULL);  // time diff
    int unix_socket;
    int host_fd;
    int ret;

    // gettimeofday(&connect_connect_router_tvStart,NULL);  // time diff
    unix_socket = connect_router ();
    // gettimeofday(&connect_connect_router_tvEnd,NULL);  // time diff

    if (DEBUG)
    {
        // printf("connect to router in unix socket: %d\n", unix_socket);
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;

    char send_buf[50] = {0};
    // char recv_buf[50] = {0}; //zx123

    msg_t msg;
    msg.msg_type = MSG_CONNECT_INVOKE_REQUEST;
    msg.listening_addr = ntohl ((sin->sin_addr).s_addr);
    msg.listening_port = ntohs (sin->sin_port);
    msg.fd_number = 0;


    memcpy (send_buf, &msg, sizeof (msg_t));

    // gettimeofday(&connect_send_tvStart,NULL);  // time diff
    ret = send (unix_socket, send_buf, sizeof (msg_t), 0);
    // gettimeofday(&connect_send_tvEnd,NULL);  // time diff
	// fprintf (connect_fp, "connect_send_tvEnd_us,%lf\n", connect_send_tvEnd_us);  // time diff

    if (ret == -1)
    {
        printf("unix_socket send error!\n");
    }

    if (DEBUG)
    {
        // printf("connect(): send to unix_socket bytes: %d\n", ret);
    }

    // printf("waiting for host_fd\n");

    // gettimeofday(&connect_recv_fd_tvStart,NULL);  // time diff
    host_fd = recv_fd (unix_socket);
    // gettimeofday(&connect_recv_fd_tvEnd,NULL);  // time diff


    // printf("recv_fd: %d\n", host_fd);


    if (DEBUG)
    {
        // printf("connect(): recv host_fd: %d\n", host_fd);

        // printf("SlimFast_epoll_fd-->%d\n", SlimFast_epoll_fd);
    }

    if (DEBUG)
    {
        // printf("dup2() return %d\n", ret);
    }

    // gettimeofday (&connect_add_del_epoll_tvStart, NULL);  // time diff

    // printf("fd_to_epoll_fd[sockfd]: %d\n", fd_to_epoll_fd[sockfd]);

    if (fd_to_epoll_fd[sockfd] > 0)
    {
        if (real_epoll.epoll_ctl (fd_to_epoll_fd[sockfd], EPOLL_CTL_DEL, sockfd, NULL) == -1)
        {
            printf("connect() epoll_ctl EPOLL_CTL_DEL error! %s\n", strerror (errno));
        }
        close (sockfd);

        ret = dup2 (host_fd, sockfd);

        if (ret == -1)
        {
            printf("connect() dup2() error!\n");
        }

        close (host_fd);

        if (real_epoll.epoll_ctl (fd_to_epoll_fd[sockfd], EPOLL_CTL_ADD, sockfd, &epoll_events[sockfd]) == -1)
        {
            printf("connect()->real_epoll.epoll_ctl()->EPOLL_CTL_ADD error: %s\n", strerror(errno));
        }
        // printf("epoll add done\n");
    }
    else
    {
        ret = dup2 (host_fd, sockfd);

        if (ret == -1)
        {
            printf("connect() dup2() error!\n");
        }

        close (host_fd); 
    }


#ifdef SECURITY

    char host_fd_buf[50];
    char recv_buf_s[50];
    security_mode_host_fd_t security_mode_host_fd;

    security_mode_host_fd.host_fd = sockfd;

    memcpy (host_fd_buf, &security_mode_host_fd, sizeof (security_mode_host_fd_t));

    if (send (unix_socket, host_fd_buf, sizeof (security_mode_host_fd_t), 0) <= 0)
    {
        printf("security mode: send host_fd number error: %s\n", strerror (errno));
    }

    if (recv (unix_socket, recv_buf_s, 50, 0) <= 0)
    {
        printf("security mode: recv response error: %s\n", strerror (errno));
    }

#endif

    // gettimeofday (&connect_add_del_epoll_tvEnd, NULL);  // time diff

    // gettimeofday(&connect_connect_tvEnd,NULL);  // time diff


    // time_diff_connect_connect = time_diff (connect_connect_tvStart, connect_connect_tvEnd);  // time diff
    // time_diff_connect_connect_router = time_diff (connect_connect_router_tvStart, connect_connect_router_tvEnd);  // time diff
    // time_diff_connect_send = time_diff (connect_send_tvStart, connect_send_tvEnd);  // time diff
    // time_diff_connect_add_del_epoll = time_diff (connect_add_del_epoll_tvStart, connect_add_del_epoll_tvEnd);  // time diff
    // time_diff_connect_recv_fd = time_diff (connect_recv_fd_tvStart, connect_recv_fd_tvEnd);  // time diff
    // time_diff_connect_dup2 = time_diff (connect_dup2_tvStart, connect_dup2_tvEnd);  // time diff


    // fprintf (connect_fp, "time_diff_connect_connect,%lf\n", time_diff_connect_connect);  // time diff
    // fprintf (connect_fp, "time_diff_connect_connect_router,%lf\n", time_diff_connect_connect_router);  // time diff
    // fprintf (connect_fp, "time_diff_connect_send,%lf\n", time_diff_connect_send);  // time diff
    // fprintf (connect_fp, "time_diff_connect_add_del_epoll,%lf\n", time_diff_connect_add_del_epoll);  // time diff
    // fprintf (connect_fp, "time_diff_connect_recv_fd,%lf\n", time_diff_connect_recv_fd);  // time diff
    // fprintf (connect_fp, "time_diff_connect_dup2,%lf\n", time_diff_connect_dup2);  // time diff


    // fflush (connect_fp);  // time diff
    // fclose (connect_fp);  // time diff



    if (DEBUG)
    {
        // printf("connect(): done\n");
    }
    // printf("connect done!\n");

    // printf("sockfd: %d\n", sockfd);

    close (unix_socket);
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{

    if (DEBUG)
    {
        // printf("call accept() \n");
    }
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
	{
    	perror("getsockname");
	}
	else
	{
    	// printf("port number %d\n", ntohs(sin.sin_port));
	}

	uint16_t listening_port; 
	// uint32_t unix_sock;
	uint32_t host_fd;

	listening_port = ntohs (sin.sin_port);   

    if (DEBUG)
    {
        printf("accept listening_ip is %s, port is %d\n", inet_ntoa(sin.sin_addr), listening_port);
    }

    host_fd = recv_fd (sockfd);  


#ifdef SECURITY

    char *host_fd_buf[50];
    char *recv_buf[50];
    security_mode_host_fd_t security_mode_host_fd;

    security_mode_host_fd.host_fd = host_fd;

    memcpy (host_fd_buf, &security_mode_host_fd, sizeof (security_mode_host_fd_t));

    if (send (sockfd, host_fd_buf, sizeof (security_mode_host_fd_t), 0) <= 0)
    {
        printf("security mode: send host_fd number error: %s\n", strerror (errno));
    }

    if (recv (sockfd, recv_buf, 50, 0) <= 0)
    {
        printf("security mode: recv response error: %s\n", strerror (errno));
    }

#endif


    getsockname (host_fd, addr, addrlen);

    if (DEBUG)
    {
        // printf("accept host_fd is %d\n", host_fd);
    }

	return host_fd;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    
    if (DEBUG)
    {
        // printf("call accept4() \n");
    }
    
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
    {
        perror("getsockname");
    }
    else
    {
        if (DEBUG)
        {
            // printf("port number %d\n", ntohs(sin.sin_port));
        }
    }

    uint16_t listening_port;
    // uint32_t unix_sock; //zx123
    uint32_t host_fd;

    listening_port = ntohs (sin.sin_port);
    if (DEBUG)
    {
        printf("accept listening_port is %d\n", listening_port);
    }


    host_fd = recv_fd (sockfd);


#ifdef SECURITY

    char *host_fd_buf[50];
    char *recv_buf[50];
    security_mode_host_fd_t security_mode_host_fd;

    security_mode_host_fd.host_fd = host_fd;

    memcpy (host_fd_buf, &security_mode_host_fd, sizeof (security_mode_host_fd_t));

    if (send (sockfd, host_fd_buf, sizeof (security_mode_host_fd_t), 0) <= 0)
    {
        printf("security mode: send host_fd number error: %s\n", strerror (errno));
    }

    if (recv (sockfd, recv_buf, 50, 0) <= 0)
    {
        printf("security mode: recv response error: %s\n", strerror (errno));
    }

#endif


    flags = fcntl(host_fd, F_GETFL, 0);
    fcntl(host_fd, F_SETFL, flags | O_NONBLOCK);

    if (DEBUG)
    {
        // printf("accept host_fd is %d\n", host_fd);

        // printf("accept4() recv test\n");
    }

    getsockname (host_fd, addr, addrlen);

    return host_fd;
}

void InsertHashToPacket(void **buf, size_t msg_len, uint64_t hash)
{
    char* sendto_buf;
    char hash_key[21];
    snprintf (hash_key, sizeof(hash_key), "%ld%s",hash, "*");

    sendto_buf = (char*)malloc(strlen(hash_key) + msg_len + 1);
    memset(sendto_buf, 0, strlen(hash_key) + msg_len + 1);

    strcpy(sendto_buf, hash_key);
    if (debug_flag) 
        printf("[InsertHashToPacket] ori msg_len %ld\n", msg_len);
    memcpy(sendto_buf + strlen(hash_key), *buf, msg_len);
    if (debug_flag) 
        printf("[InsertHashToPacket] later msg_len %ld\n", strlen(sendto_buf));

    *buf = sendto_buf;
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
        if (len>21) 
        {
            return 0;
        }
    }
    recv_buf++;
    hash_key[len] = '\0';
    if (debug_flag) 
        printf("GetHashViaPacket (char)hash_key %s\n", hash_key);
    recv_buf[strlen(buf)-strlen(hash_key)-1] = '\0';
    strcpy(buf, recv_buf);

    uint64_t hash_num = strtol((char *)hash_key, &temp_buf, 10);
    if (debug_flag) 
        printf("hash_num %ld\n", hash_num);
    return hash_num;
}

ssize_t sendto(int socket, const void *buf, size_t msg_len, int flags, const struct sockaddr *to, socklen_t tolen)
{
    if (debug_flag) 
        printf("[ROLE %d]=======================================[SENDTO]======================================\n", fd_table[socket]);

    struct sockaddr_in *sin = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    uint32_t to_addr = ntohl ((((struct sockaddr_in *)to)->sin_addr).s_addr);
    uint16_t to_port = ntohs (((struct sockaddr_in *)to)->sin_port);
    uint64_t hash = GetHash2(
        ntohl ((((struct sockaddr_in *)to)->sin_addr).s_addr), ntohs (((struct sockaddr_in *)to)->sin_port)
    );
    bool need_hash = true;
    if ( fd_table[socket]==CLIENT_FD )
    {
        hash_node_t *host_node = hash_table_search(server_host_info, hash);
        if ( host_node==NULL ) 
        { 
            int unix_socket = connect_UDProuter ();
            char send_buf_t[256];
            char recv_buf_t[256];
            hash_msg *msg = (hash_msg *)malloc(sizeof(hash_msg));
            msg->req_type = MSG_SEARCH_HOST_ADDR_INVOKE_REQUEST;
            msg->hash_key = 0;
            msg->m_addr = to_addr;
            msg->m_port = 0;
            memcpy (send_buf_t, msg, sizeof (hash_msg));
            int send_ret = send (unix_socket, send_buf_t, sizeof(hash_msg), 0);
            if ( send_ret == -1 )
            {
               perror("unix_sock send error!\n");
            }
            else
            {
                if (debug_flag)
                    printf("send_ret %d\n", send_ret);
            }
            int recv_ret = recv(unix_socket, recv_buf_t, 256, 0);
            if ( recv_ret<0 )
            {
                perror("UPDATE CLIENT HOST INFO FAILD\n");
                return 0;
            }
            real_socket.close(unix_socket);
            msg = (hash_msg *)recv_buf_t;
            uint32_t host_addr = msg->m_addr; 
            hash_table_insert(server_host_info, hash, host_addr, LISTEN_PORT);
            sin->sin_addr.s_addr = htonl(host_addr);
            sin->sin_port = htons(LISTEN_PORT);
            sin->sin_family = AF_INET;
        }
        else
        { 
            sin->sin_addr.s_addr = htonl(host_node->m_addr);
            sin->sin_port = htons(host_node->m_port);
            sin->sin_family = AF_INET;
            if ( host_node->m_port!=LISTEN_PORT ) 
                need_hash = false;
        }
    }else if ( fd_table[socket]==SERVER_FD )
    {
        sin = (struct sockaddr_in *)to;
        hash = fd_to_hash_table[socket]; 
        uint64_t client_hash = GetHash2(ntohl ((sin->sin_addr).s_addr), ntohs (sin->sin_port));
        hash_node_t *client_node = hash_table_search(client_need_hash_table, client_hash);
        if ( client_node!=NULL )
            need_hash = false; 
    }

    void *sendto_buf = buf;
    if ( need_hash )
        InsertHashToPacket(&sendto_buf, msg_len, hash);

    int ret = real_socket.sendto(socket, sendto_buf, strlen(sendto_buf) + 1, flags, (struct sockaddr *)sin, tolen);
    return ret - (strlen(sendto_buf) - msg_len);
}

ssize_t recvfrom(int socket, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t * addr_len)
{
    int ret = real_socket.recvfrom(socket, buf, n, flags, addr, addr_len);

    if ( fd_table[socket]==SERVER_FD && ntohs (((struct sockaddr_in *)addr)->sin_port)!=LISTEN_PORT ) 
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        uint64_t client_hash = GetHash2(ntohl ((sin->sin_addr).s_addr), ntohs (sin->sin_port));
        hash_node_t *client_node = hash_table_search(client_need_hash_table, client_hash);
        if ( client_node==NULL )
            hash_table_insert(client_need_hash_table, client_hash, 1, 1);
        return ret;
    }

    uint64_t hash_key = GetHashViaPacket(buf);
    if ( hash_key==0 ) 
        return strlen(buf);

    if ( fd_table[socket]==CLIENT_FD )
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        hash_node_t *host_node = hash_table_search(server_host_info, hash_key);
        if ( host_node==NULL )
        {
            perror("[RECVFROM] ERROR!The client received an unrecognized server\n");
            return 1;
        }
        if ( host_node->m_port==LISTEN_PORT )
        {
            host_node->m_port = ntohs(sin->sin_port); 
            uint64_t host_hash = GetHash2(host_node->m_addr, host_node->m_port);
            hash_table_insert(server_host_info, host_hash, host_node->m_addr, host_node->m_port);
        }
    }
    if ( fd_table[socket]==SERVER_FD && hash_key!=fd_to_hash_table[socket] ) 
    {
        hash_node_t *client_node = hash_table_search(client_host_info, hash_key);
        if ( client_node==NULL )
        {
            client_node = (hash_node_t *)malloc(sizeof(hash_node_t));
            int unix_socket = connect_UDProuter();
            char send_buf_t[256];
            char recv_buf_t[256];
            hash_msg *msg = (hash_msg *)malloc(sizeof(hash_msg));
            msg->req_type = MSG_SEARCH_CLIENT_INVOKE_REQUEST;
            msg->hash_key = hash_key;
            msg->m_addr = 0;
            msg->m_port = 0;
            memcpy (send_buf_t, msg, sizeof (hash_msg));
            int send_ret = send (unix_socket, send_buf_t, sizeof(hash_msg), 0);
            if ( send_ret == -1 )
            {
               perror("unix_sock send error!\n");
            }
            else
            {
                if (debug_flag)
                    printf("send_ret %d\n", send_ret);
            }
            int recv_ret = recv(unix_socket, recv_buf_t, 256, 0);
            if ( recv_ret<0 )
            {
                perror("UPDATE CLIENT HOST INFO FAILD\n");
                return 0;
            }
            msg = (hash_msg *)recv_buf_t;
            hash_table_insert(client_host_info, hash_key, msg->m_addr, msg->m_port);
            client_node->m_addr = msg->m_addr;
            client_node->m_port = msg->m_port;
            real_socket.close(unix_socket);
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(client_node->m_port);
        sin->sin_addr.s_addr = htonl(client_node->m_addr);
    }
    return strlen(buf);
}

