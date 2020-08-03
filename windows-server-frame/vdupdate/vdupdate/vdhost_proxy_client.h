#ifndef _GUEST_AGENT_H_
#define _GUEST_AGENT_H_
#include <stdio.h>
#include <string.h>
#include "socket_client.h"

class VdhostProxyClient
{
public:
	VdhostProxyClient(char *host, int port, socket_cbk_t cbk){
		strcpy(this->_host, host);
		this->_port = port;
		this->_cbk = cbk;
	}
	int start();
	void stop();

	int send(void *data, int len);

public:
	SOCKET sock;

private:
	char _host[32];
	int _port;
	socket_cbk_t _cbk;
};

#endif //_GUEST_AGENT_H_
