#pragma once

#include <string>
#include <string.h>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include "../common/mongoose.h"

#define ERROR_INTERNEL "{\"message\":\"internel error!\",\"ret_code\":5000}"
#define ERROR_UNSUPPORT_HTTP_METHOD "{\"message\":\"unsupport http method!\",\"ret_code\":5001}"
#define ERROR_NO_HTTP_METHOD_HANDLER "{\"message\":\"have no http message handler!\",\"ret_code\":5002}"
#define ERROR_NO_ROUTER "{\"message\":\"have no router!\",\"ret_code\":5003}"


// http result callback
typedef void OnRspCallback(mg_connection *c, std::string);

//http request handler
using ReqHandler = std::function<bool (std::string, std::string, mg_connection *c, OnRspCallback)>;

class HttpServer
{
public:
	HttpServer() {}
	~HttpServer() {}
	void Init(const std::string &port); // init http port
	bool Start();
	bool Close();
	void AddHandler(const std::string &url, ReqHandler req_handler);
	void RemoveHandler(const std::string &url);
	static std::string s_web_dir; // web root path
	static mg_serve_http_opts s_server_option; // web server option
	static std::unordered_map<std::string, ReqHandler> s_handler_map; // callback handler map

private:
	static void OnHttpWebsocketEvent(mg_connection *connection, int event_type, void *event_data);
	static void HandleHttpEvent(mg_connection *connection, http_message *http_req);
	static void SendHttpRsp(mg_connection *connection, std::string rsp);
	static int isWebsocket(const mg_connection *connection); // is websoket connection
	static void HandleWebsocketMessage(mg_connection *connection, int event_type, websocket_message *ws_msg); 
	static void SendWebsocketMsg(mg_connection *connection, std::string msg);
	static void BroadcastWebsocketMsg(std::string msg);
	static std::unordered_set<mg_connection *> s_websocket_session_set; // websocket connections

	std::string m_port;    // port
	mg_mgr m_mgr;          // connection manager
};

