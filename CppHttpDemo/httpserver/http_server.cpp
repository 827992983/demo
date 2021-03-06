#include <utility>
#include "http_server.h"

// init static variable
mg_serve_http_opts HttpServer::s_server_option;
std::string HttpServer::s_web_dir = "./web";
std::unordered_map<std::string, ReqHandler> HttpServer::s_handler_map;
std::unordered_set<mg_connection *> HttpServer::s_websocket_session_set;

void HttpServer::Init(const std::string &port)
{
	m_port = port;
	s_server_option.enable_directory_listing = "yes";
	s_server_option.document_root = s_web_dir.c_str();

	// other http setting

	// enable CORS
	// s_server_option.extra_headers = "Access-Control-Allow-Origin: *";
}

bool HttpServer::Start()
{
	mg_mgr_init(&m_mgr, NULL);
	mg_connection *connection = mg_bind(&m_mgr, m_port.c_str(), HttpServer::OnHttpWebsocketEvent);
	if (connection == NULL)
		return false;
	// for both http and websocket
	mg_set_protocol_http_websocket(connection);

	printf("starting http server at port: %s\n", m_port.c_str());
	// loop
	while (true)
		mg_mgr_poll(&m_mgr, 500); // ms

	return true;
}

void HttpServer::OnHttpWebsocketEvent(mg_connection *connection, int event_type, void *event_data)
{
	// websocket
	if (event_type == MG_EV_HTTP_REQUEST)
	{
		http_message *http_req = (http_message *)event_data;
		HandleHttpEvent(connection, http_req);
	}
	else if (event_type == MG_EV_WEBSOCKET_HANDSHAKE_DONE ||
		     event_type == MG_EV_WEBSOCKET_FRAME ||
		     event_type == MG_EV_CLOSE)
	{
		websocket_message *ws_message = (struct websocket_message *)event_data;
		HandleWebsocketMessage(connection, event_type, ws_message);
	}
}

// ---- simple http ---- //
static bool route_check(http_message *http_msg, char *route_prefix)
{
	if (mg_vcmp(&http_msg->uri, route_prefix) == 0)
		return true;
	else
		return false;
}

void HttpServer::AddHandler(const std::string &url, ReqHandler req_handler)
{
	if (s_handler_map.find(url) != s_handler_map.end())
		return;

	s_handler_map.insert(std::make_pair(url, req_handler));
}

void HttpServer::RemoveHandler(const std::string &url)
{
	auto it = s_handler_map.find(url);
	if (it != s_handler_map.end())
		s_handler_map.erase(it);
}

void HttpServer::SendHttpRsp(mg_connection *connection, std::string rsp)
{
	// --- disable CORS
	// sender header
	mg_printf(connection, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
	// return json
	mg_printf_http_chunk(connection, "%s", rsp.c_str());
	// send empty string to stop response
	mg_send_http_chunk(connection, "", 0);

	// --- enable CORS
	/*mg_printf(connection, "HTTP/1.1 200 OK\r\n"
			  "Content-Type: text/plain\n"
			  "Cache-Control: no-cache\n"
			  "Content-Length: %d\n"
			  "Access-Control-Allow-Origin: *\n\n"
			  "%s\n", rsp.length(), rsp.c_str()); */
}

void HttpServer::HandleHttpEvent(mg_connection *connection, http_message *http_req)
{
	std::string result;
	std::string req_str = std::string(http_req->message.p, http_req->message.len);

	//printf("got request: %s\n", req_str.c_str());

	/* Filter callback */ 
	std::string url = std::string(http_req->uri.p, http_req->uri.len);
	auto it = s_handler_map.find(url);
	if (it != s_handler_map.end())
	{
		if(mg_vcmp(&http_req->method, "POST") == 0 || mg_vcmp(&http_req->method, "post") == 0){
			std::string body = std::string(http_req->body.p, http_req->body.len);
			ReqHandler handle_func = it->second;
			handle_func(url, body, connection, &HttpServer::SendHttpRsp);
		}else if(mg_vcmp(&http_req->method, "GET") == 0 || mg_vcmp(&http_req->method, "get") == 0){
			std::string body = std::string(http_req->query_string.p, http_req->query_string.len);
			ReqHandler handle_func = it->second;
			handle_func(url, body, connection, &HttpServer::SendHttpRsp);
		}else{
			result = ERROR_UNSUPPORT_HTTP_METHOD;
			SendHttpRsp(connection, result);
		}
		return;
	}

	/* Request router */
	if (route_check(http_req, "/")){
		mg_serve_http(connection, http_req, s_server_option); // index page
	}else if (route_check(http_req, "/api")) {
		if(mg_vcmp(&http_req->method, "GET") == 0 || mg_vcmp(&http_req->method, "get") == 0){
			result = ERROR_NO_HTTP_METHOD_HANDLER;
			SendHttpRsp(connection, result);
		}else if(mg_vcmp(&http_req->method, "POST") == 0 || mg_vcmp(&http_req->method, "post") == 0){
			result = ERROR_NO_HTTP_METHOD_HANDLER;
			SendHttpRsp(connection, result);
		}else if (mg_vcmp(&http_req->method, "PUT") == 0 || mg_vcmp(&http_req->method, "put") == 0){
			result = ERROR_UNSUPPORT_HTTP_METHOD;
			SendHttpRsp(connection, result);
		}else if (mg_vcmp(&http_req->method, "DELETE") == 0 || mg_vcmp(&http_req->method, "delete") == 0){
			result = ERROR_UNSUPPORT_HTTP_METHOD;
			SendHttpRsp(connection, result);
		}else{
			result = ERROR_UNSUPPORT_HTTP_METHOD;
			SendHttpRsp(connection, result);
		}	
	}else{
		result = ERROR_NO_ROUTER;
		SendHttpRsp(connection, result);
	}
}

// ---- websocket ---- //
int HttpServer::isWebsocket(const mg_connection *connection)
{
	return connection->flags & MG_F_IS_WEBSOCKET;
}

void HttpServer::HandleWebsocketMessage(mg_connection *connection, int event_type, websocket_message *ws_msg)
{
	if (event_type == MG_EV_WEBSOCKET_HANDSHAKE_DONE)
	{
		printf("client websocket connected\n");
		// client ip and port
		char addr[32];
		mg_sock_addr_to_str(&connection->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
		printf("client addr: %s\n", addr);

		// add session
		s_websocket_session_set.insert(connection);

		SendWebsocketMsg(connection, "client websocket connected");
	}
	else if (event_type == MG_EV_WEBSOCKET_FRAME)
	{
		mg_str received_msg = {
			(char *)ws_msg->data, ws_msg->size
		};

		char buff[1024] = {0};
		strncpy(buff, received_msg.p, received_msg.len); // must use strncpy, specifiy memory pointer and length

		// do sth to process request
		printf("received msg: %s\n", buff);
		SendWebsocketMsg(connection, "send your msg back: " + std::string(buff));
		//BroadcastWebsocketMsg("broadcast msg: " + std::string(buff));
	}
	else if (event_type == MG_EV_CLOSE)
	{
		if (isWebsocket(connection))
		{
			printf("client websocket closed\n");
			// �Ƴ�session
			if (s_websocket_session_set.find(connection) != s_websocket_session_set.end())
				s_websocket_session_set.erase(connection);
		}
	}
}

void HttpServer::SendWebsocketMsg(mg_connection *connection, std::string msg)
{
	mg_send_websocket_frame(connection, WEBSOCKET_OP_TEXT, msg.c_str(), strlen(msg.c_str()));
}

void HttpServer::BroadcastWebsocketMsg(std::string msg)
{
	for (mg_connection *connection : s_websocket_session_set)
		mg_send_websocket_frame(connection, WEBSOCKET_OP_TEXT, msg.c_str(), strlen(msg.c_str()));
}

bool HttpServer::Close()
{
	mg_mgr_free(&m_mgr);
	return true;
}
