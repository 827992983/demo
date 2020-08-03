#include "stdafx.h"
#include "vdhost_proxy_client.h"
#include <stdio.h>
#include "logger.h"
#include "cJSON.h"
#include "request.h"
#include "vdupdate_global.h"

extern int g_vdhost_proxy_not_register;

///////////////////////////////////////////// build request /////////////////////////////////////////////
static cJSON *build_request(const char *action)
{
	cJSON *jsonRequest;  
	DWORD size = 20;
	jsonRequest=cJSON_CreateObject();    
	cJSON_AddStringToObject(jsonRequest, "action", action);  
	return jsonRequest;
}

char *build_request_register()
{   
	cJSON *jsonRequest = build_request(REQUEST_VDUPDATE_SERVER_REGISTER);
	cJSON_AddStringToObject(jsonRequest, "role", "vdupdate");
	char *ret = cJSON_Print(jsonRequest);
	cJSON_Delete(jsonRequest);
	return ret;
}

char *build_request_unregister()
{   
	cJSON *jsonRequest = build_request(REQUEST_VDUPDATE_SERVER_UNREGISTER);
	cJSON_AddStringToObject(jsonRequest, "role", "vdupdate");
	char *ret = cJSON_Print(jsonRequest);
	cJSON_Delete(jsonRequest);
	return ret;
}

char *build_request_ping()
{   
	cJSON *jsonRequest = build_request(REQUEST_VDUPDATE_SERVER_PING);
	cJSON_AddStringToObject(jsonRequest, "role", "vdupdate");
	char *ret = cJSON_Print(jsonRequest);
	cJSON_Delete(jsonRequest);
	return ret;
}

char *build_request_spice_client_connected(char *client_ip)
{   
	
	return NULL;
}



///////////////////////////////////////////// handle response /////////////////////////////////////////////

static int get_request_ret_code(const char *response)
{
	int ret_code = -1;
	cJSON *jsonRequest = cJSON_Parse(response);
	if(jsonRequest == NULL) return -1;
	cJSON *jsonRetCode = cJSON_GetObjectItem(jsonRequest,"ret_code");
	if(jsonRetCode == NULL) return -1;
	ret_code = jsonRetCode->valueint;
	cJSON_Delete(jsonRequest);
	return 0;
}

static int get_request_err_msg(const char *response, char *err_msg)
{
	cJSON *jsonRequest = cJSON_Parse(response);
	if(jsonRequest == NULL) return -1;
	cJSON *jsonRetCode = cJSON_GetObjectItem(jsonRequest,"ret_code");
	if(jsonRetCode == NULL) return -1;
	strcpy(err_msg, jsonRetCode->valuestring);
	cJSON_Delete(jsonRequest);
	return 0;
}

void handle_response_register(const char *response)
{
	char file[256] = {0};
	char section[32] = {0};
	char key[32] = {0};
	cJSON *jsonResponse = cJSON_Parse(response);
	if(jsonResponse == NULL)
	{
		LOG_ERROR("receive response [%s] error.");
		return;
	}

	int ret_code = ret_code = get_request_ret_code(response);
	if (ret_code != RET_CODE_SUCCESS)
	{
		char errmsg[256] = {0};
		get_request_err_msg(response, errmsg);
		cJSON_Delete(jsonResponse);
		LOG_ERROR("ret_code = %d, err_msg = %s", ret_code, errmsg);
		return;
	}

	g_vdhost_proxy_not_register = 0;

	cJSON_Delete(jsonResponse);
	LOG_INFO("handler register success");
	return;
}

void handle_response_unregister(const char *response)
{
	cJSON *jsonResponse = cJSON_Parse(response);
	if(jsonResponse == NULL)
	{
		LOG_ERROR("receive response [%s] error.");
		return;
	}

	int ret_code = ret_code = get_request_ret_code(response);
	if (ret_code != RET_CODE_SUCCESS)
	{
		char errmsg[256] = {0};
		get_request_err_msg(response, errmsg);
		cJSON_Delete(jsonResponse);
		LOG_ERROR("ret_code = %d, err_msg = %s", ret_code, errmsg);
		return;
	}

	cJSON_Delete(jsonResponse);
	LOG_INFO("handler unregister success");
	return;
}

void handle_response_ping(const char *response)
{
	cJSON *jsonResponse = cJSON_Parse(response);
	if(jsonResponse == NULL)
	{
		LOG_ERROR("receive response [%s] error.");
		return;
	}

	int ret_code = ret_code = get_request_ret_code(response);
	if (ret_code != RET_CODE_SUCCESS)
	{
		char errmsg[256] = {0};
		get_request_err_msg(response, errmsg);
		cJSON_Delete(jsonResponse);
		LOG_ERROR("ret_code = %d, err_msg = %s", ret_code, errmsg);
		return;
	}

	cJSON_Delete(jsonResponse);
	return;
}