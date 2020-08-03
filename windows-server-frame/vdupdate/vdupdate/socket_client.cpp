#include "stdafx.h"
#include "socket_client.h"
#include "logger.h"

#define HEADER_NAME "qing-cloud"
#define HEADER_NAME_SIZE strlen(HEADER_NAME)
#define HEADER_LENGTH 14
#define SEND_MAX_BUFF  1024
#define RECV_MAX_BUFF  1024

typedef struct _SOCKET_THREAD_PARAM
{
	SOCKET sock;
	socket_cbk_t cbk;
}SOCKET_THREAD_PARAM;

DWORD WINAPI worker_thread(LPVOID lpThreadParameter)  
{  
    SOCKET_THREAD_PARAM* pThread = (SOCKET_THREAD_PARAM*)lpThreadParameter;
    socket_cbk_t cbk = pThread->cbk;
    SOCKET sock = pThread->sock;
	int total_len =0, recv_len = 0;
	int ret = 0;
	char length_buf[4] = {0};
	int length = 0;
	char *header = (char *)malloc(sizeof(char) * HEADER_LENGTH);
	char *data = (char *)malloc(sizeof(char) * RECV_MAX_BUFF);
	memset(header, 0, HEADER_LENGTH);
    memset(data, 0, RECV_MAX_BUFF);

	fd_set sock_set; 

    while(1)
    {
		FD_ZERO(&sock_set);  
		FD_SET(sock, &sock_set);  
		ret = select(sock+1, &sock_set, NULL, NULL, NULL);
		if(ret == SOCKET_ERROR)
		{
			LOG_ERROR("select SOCKET_ERROR");
			break;
		}

		if (ret > 0)
		{
			if(FD_ISSET(sock, &sock_set))
			{
				//read data
				ret = recv(sock, header, HEADER_LENGTH, 0);
				if(ret < HEADER_LENGTH)
				{
					LOG_ERROR("read socket error, ret [%d]", ret);
					break;
				}

				char name[11];
				memcpy(name, header, HEADER_NAME_SIZE);
				name[10] = '\0';
				if (strcmp(name, HEADER_NAME) != 0)
				{
					LOG_ERROR("header is error.\n");
					break;
				}
				
				memcpy(&length, header+HEADER_NAME_SIZE, 4);
				total_len = length - HEADER_LENGTH;
				while(recv_len < total_len)
				{
					ret = recv(sock,data + recv_len,total_len - recv_len,0);
					if(ret < 0)
					{
						LOG_ERROR("read data error, ret = %d", ret);
						break;
					}
					if(ret > 0)
					{
						recv_len += ret;
					}
				}
				LOG_INFO("recv data: %s\n",data);
				if (total_len == recv_len)
				{
					cbk(sock, data);
					memset(data, 0, RECV_MAX_BUFF);
					memset(header, 0 ,HEADER_LENGTH);
					total_len = 0;
					recv_len = 0;
				}
			}
		}
    }
	free(header);
	free(data);
    return 0;
}

int init_socket()  
{  
    return 0;
}  

SOCKET socket_client_connect(char *host, int port, socket_cbk_t cbk)
{
    WSAEVENT wsaEvent;
    SOCKET sock;
	struct sockaddr_in sin;

	sin.sin_family = AF_INET;  
	sin.sin_port = htons(port);   
	sin.sin_addr.S_un.S_addr = inet_addr(host); 

	if (init_socket() != 0)
	{
		LOG_ERROR("init socket error");
		return NULL;
	}

    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock == INVALID_SOCKET)
    {
		LOG_ERROR("create socket error.");
        return NULL;
    }

    int ret = -1;
    if((ret = connect(sock,(struct sockaddr*)&sin,sizeof(SOCKADDR_IN))) !=0)
    {
		LOG_ERROR("connect server fail\n");
		closesocket(sock);
		return NULL;
    }
	
	//unsigned long ul = 1;
	//ioctlsocket(sock, FIONBIO, &ul); //set no block

    SOCKET_THREAD_PARAM* pThreadParam = (SOCKET_THREAD_PARAM*)malloc(sizeof(SOCKET_THREAD_PARAM));
    pThreadParam->sock = sock;
    pThreadParam->cbk = cbk;

    HANDLE hThread = CreateThread(NULL, 0, worker_thread, (LPVOID)pThreadParam, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }
	CloseHandle(hThread);

    return sock;
}

void socket_close(SOCKET sock)
{
    closesocket(sock);
}

int socket_send(SOCKET sock, void *data, int len)
{
	char buf[SEND_MAX_BUFF] = {0};
	int ret = 0;

	len += 14;

	memcpy(buf, "qing-cloud", 10);
	memcpy(buf+10, &len, 4);
	memcpy(&buf[14],data,len);

	ret = send(sock, buf, len, 0);
	LOG_INFO("send len(%d) DATA: %s", ret, data);
	return ret;
}
