#ifndef _VDA_SERVER_REQUEST_H__
#define _VDA_SERVER_REQUEST_H__

//request
#define REQUEST_VDUPDATE_SERVER_REGISTER "ProxyRegister"
#define REQUEST_VDUPDATE_SERVER_UNREGISTER "ProxyUnRegister"
#define REQUEST_VDUPDATE_SERVER_PING "ProxyPing"


//response
#define RESPONSE_VDUPDATE_SERVER_REGISTER "ProxyRegisterResponse"
#define RESPONSE_VDUPDATE_SERVER_UNREGISTER "ProxyUnRegisterResponse"
#define RESPONSE_VDUPDATE_SERVER_PING "ProxyPingResponse"


#define RET_CODE_SUCCESS 0

char *build_request_register();
char *build_request_unregister();
char *build_request_ping();

void handle_response_register(const char *response);
void handle_response_unregister(const char *response);
void handle_response_ping(const char *response);

#endif
