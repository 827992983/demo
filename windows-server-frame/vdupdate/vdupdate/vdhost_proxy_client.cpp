#include "stdafx.h"
#include "vdhost_proxy_client.h"


int VdhostProxyClient::start()
{
	sock = socket_client_connect(this->_host, this->_port, this->_cbk);
	if(sock == INVALID_SOCKET){
		return -1;
	}
	return 0;
}

void VdhostProxyClient::stop()
{
	socket_close(sock);
	sock = INVALID_SOCKET;
}

int VdhostProxyClient::send(void *data, int len)
{
	if (sock == INVALID_SOCKET)
	{
		return -1;
	}
	return socket_send(sock, data, len);
}
