#ifndef _SOCKET_CLIENT_H_
#define _SOCKET_CLIENT_H_

#ifdef __cplusplus
extern "C"{
#endif

#include <winsock2.h> //winsock2.h must been included on the top
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef void (* socket_cbk_t)(SOCKET sock, void *data);

SOCKET socket_client_connect(char *host, int port, socket_cbk_t cbk);
int socket_send(SOCKET sock, void *data, int len);
void socket_close(SOCKET sock);

#ifdef __cplusplus
}
#endif

#endif //_SOCKET_CLIENT_H_
