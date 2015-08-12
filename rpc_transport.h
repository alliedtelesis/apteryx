#ifndef _RPC_TRANSPORT_H_
#define _RPC_TRANSPORT_H_
#include <pthread.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef uint64_t rpc_id;
typedef struct rpc_socket_s *rpc_socket;
typedef struct rpc_server_s *rpc_server;
typedef struct rpc_service_s *rpc_service;
typedef void (*rpc_callback) (rpc_socket, rpc_id, void *data, size_t len);

struct rpc_socket_s {
    pthread_mutex_t lock;
    int refcount;
    int sock;
    void *priv;
    rpc_server parent;
    pthread_mutex_t out_lock;
    rpc_id next_id;

    pthread_t thread;
    rpc_callback request_cb;

    pthread_mutex_t in_lock;
    pthread_cond_t in_cond;
    GList *in_queue;
    int waiting;
    bool dead;
};

struct rpc_server_s {
    int sock;
    rpc_service parent;
    pthread_t thread;
    pthread_mutex_t lock;
    char *url;
    char *guid;
    GList *clients;
    rpc_callback request_cb;
};

struct rpc_service_s {
    pthread_mutex_t lock;
    GList *servers;
    rpc_callback request_cb;
    void *priv;
};

rpc_service rpc_service_init (rpc_callback request_callback, void *priv);
void *rpc_service_priv_get (rpc_service s);
bool rpc_service_run (rpc_service s, int stopfd);
rpc_server rpc_service_find_server (rpc_service s, const char *url);
bool rpc_service_die (rpc_service s);
bool rpc_service_bind_url (rpc_service s, const char *guid, const char *url);
bool rpc_service_unbind_url (rpc_service s, const char *guid);

rpc_service rpc_server_parent_get (rpc_server s);

rpc_socket rpc_socket_connect_service (const char *url, rpc_callback request_callback);

rpc_socket rpc_socket_create (int fd, rpc_callback cb, rpc_server parent);
void rpc_socket_ref (rpc_socket sock);
void rpc_socket_deref (rpc_socket sock);

void *rpc_socket_priv_get (rpc_socket s);
rpc_server rpc_socket_parent_get (rpc_socket s);

rpc_id rpc_socket_send_request (rpc_socket sock, void *data, size_t len);
bool rpc_socket_send_response (rpc_socket sock, rpc_id id, void *data, size_t len);
bool rpc_socket_recv (rpc_socket sock, rpc_id id, void **data, size_t *len, uint64_t waitUS);

rpc_socket rpc_socket_current (void);
void rpc_socket_current_set (rpc_socket sock);

#endif /* _RPC_TRANSPORT_H_ */
