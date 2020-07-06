#include <iostream>
#include <memory>
#include "http_server.h"

bool handle_router_api(std::string url, std::string body, mg_connection *c, OnRspCallback rsp_callback)
{
	// do sth
	std::cout << "==========================handle api=====================" << std::endl;
	std::cout << "url: " << url << std::endl;
	std::cout << "body: " << body << std::endl;

	struct mg_str http_req = {0};
	http_req.p = new char[100];
	http_req.len = 100;
	memcpy((void *)(http_req.p), body.c_str(), strlen(body.c_str()));
	http_req.len = strlen(body.c_str());

	char n1[100] = {0};
	char n2[100] = {0};

	mg_get_http_var(&http_req, "n1", n1, sizeof(n1));
	mg_get_http_var(&http_req, "n2", n2, sizeof(n2));

	std::cout << "n1=" << n1 << std::endl;
	std::cout << "n2=" << n2 << std::endl;

	rsp_callback(c, "aaaaaaa");

	std::cout << "==========================END=====================" << std::endl;
	return true;
}

int main(int argc, char *argv[]) 
{
	std::string port = "8001";
	auto http_server = std::shared_ptr<HttpServer>(new HttpServer);
	http_server->Init(port);
	// add handler
	http_server->AddHandler("/api", handle_router_api);
	http_server->Start();
	

	return 0;
}