#include <iostream>
#include "http_client.h"

void handle_func(std::string rsp)
{
	// do sth according to rsp
	std::cout << "http response: " << rsp << std::endl;
}

int main()
{
	std::string url1 = "http://127.0.0.1:8001/api";
	HttpClient::SendHttpGetReq(url1, handle_func);
	
	HttpClient::s_exit_flag = 0;
	std::string url2 = "http://127.0.0.1:8001/test";
	HttpClient::SendHttpGetReq(url2, [](std::string rsp) { 
		std::cout << "http rsp2: " << rsp << std::endl; 
	});

	

	return 0;
}