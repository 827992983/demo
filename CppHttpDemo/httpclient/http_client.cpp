#include "http_client.h"

// init client
int HttpClient::s_exit_flag = 0;
ReqCallback HttpClient::s_req_callback;

// client reponse handler
void HttpClient::OnHttpEvent(mg_connection *connection, int event_type, void *event_data)
{
	http_message *hm = (struct http_message *)event_data;
	int connect_status;

	switch (event_type) 
	{
	case MG_EV_CONNECT:
		connect_status = *(int *)event_data;
		if (connect_status != 0) 
		{
			printf("Error connecting to server, error code: %d\n", connect_status);
			s_exit_flag = 1;
		}
		break;
	case MG_EV_HTTP_REPLY:
	{
		//printf("Got reply:\n%.*s\n", (int)hm->body.len, hm->body.p);
		std::string rsp = std::string(hm->body.p, hm->body.len);
		connection->flags |= MG_F_SEND_AND_CLOSE;
		s_exit_flag = 1; // close connection flag in every request
        
		// handle
		s_req_callback(rsp);
	}
		break;
	case MG_EV_CLOSE:
		if (s_exit_flag == 0) 
		{
			printf("Server closed connection\n");
			s_exit_flag = 1;
		};
		break;
	default:
		break;
	}
}


// sned GET request, handle it and close
void HttpClient::SendHttpGetReq(const std::string &url, ReqCallback req_callback)
{
	s_req_callback = req_callback;
	mg_mgr mgr;
	mg_mgr_init(&mgr, NULL);
	auto connection = mg_connect_http(&mgr, OnHttpEvent, url.c_str(), NULL, "n1=value_1&n2=value_2");
	mg_set_protocol_http_websocket(connection);

	printf("Send http GET request %s\n", url.c_str());

	// loop
	while (s_exit_flag == 0)
		mg_mgr_poll(&mgr, 500);

	mg_mgr_free(&mgr);
}

//  send POST request, handle it and close
void HttpClient::SendHttpPostReq(const std::string &url, ReqCallback req_callback)
{
	s_req_callback = req_callback;
	mg_mgr mgr;
	mg_mgr_init(&mgr, NULL);
	auto connection = mg_connect_http(&mgr, OnHttpEvent, url.c_str(), NULL, "n1=value_1&n2=value_2");
	//mg_set_protocol_http_websocket(connection);

	printf("Send http POST request %s\n", url.c_str());

	// loop
	while (s_exit_flag == 0)
		mg_mgr_poll(&mgr, 500);

	mg_mgr_free(&mgr);
}