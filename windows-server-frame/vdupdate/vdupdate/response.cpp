#include "stdafx.h"
#include "socket_client.h"
#include <stdio.h>
#include "logger.h"
#include "cJSON.h"
#include "response.h"
#include "request.h"
#include "vdupdate_global.h"


static int get_request_action(const char *request, char *action)
{
	cJSON *jsonRequest = cJSON_Parse(request);
	if(jsonRequest == NULL){ 
		LOG_ERROR("parse request [%s] error", request);
		return -1;
	}
	cJSON *jsonAction = cJSON_GetObjectItem(jsonRequest,"action");
	if(jsonAction == NULL){
		LOG_ERROR("get action JSON object error!");
		return -1;
	}
	strcpy(action, jsonAction->valuestring);
	cJSON_Delete(jsonRequest);
	return 0;
}

static int get_errmsg(const char *request, char *message)
{
	cJSON *jsonRequest = cJSON_Parse(request);
	if(jsonRequest == NULL){ 
		LOG_ERROR("parse request [%s] error", request);
		return -1;
	}
	cJSON *jsonError = cJSON_GetObjectItem(jsonRequest,"message");
	if(jsonError == NULL){
		LOG_ERROR("get error message JSON object error!");
		return -1;
	}
	strcpy(message, jsonError->valuestring);
	cJSON_Delete(jsonRequest);
	return 0;
}

static int get_ret_code(const char *request, int *ret_code)
{
	cJSON *jsonRequest = cJSON_Parse(request);
	if(jsonRequest == NULL){ 
		LOG_ERROR("parse request [%s] error", request);
		return -1;
	}
	cJSON *jsonRetCode = cJSON_GetObjectItem(jsonRequest,"ret_code");
	if(jsonRetCode == NULL){
		LOG_ERROR("get ret_code JSON object error!");
		return -1;
	}
	*ret_code = jsonRetCode->valueint;
	cJSON_Delete(jsonRequest);
	return 0;
}

static int get_request_id(const char *request, char *request_id)
{
	cJSON *jsonRequest = cJSON_Parse(request);
	if(jsonRequest == NULL) return -1;
	cJSON *jsonRequestID = cJSON_GetObjectItem(jsonRequest,"request_id");
	if(jsonRequestID == NULL) return -1;
	strcpy(request_id, jsonRequestID->valuestring);
	cJSON_Delete(jsonRequest);
	return 0;
}

static cJSON *build_response(const char *request)
{
	cJSON *jsonResponse;  
	DWORD size = 20;
	char response_action[32] = {0};
	char request_id[32] = {0};
	char action[32] = {0};
	
	get_request_action(request, action);
	get_request_id(request, request_id);
	strcpy(response_action, action);
	strcat(response_action, "_response");
	jsonResponse=cJSON_CreateObject();    
	cJSON_AddStringToObject(jsonResponse, "request_id", request_id);  
	cJSON_AddStringToObject(jsonResponse, "action", response_action);  
	return jsonResponse;
}

static cJSON *return_success(const char *request)
{
	cJSON *jsonResponse = build_response(request);
	cJSON_AddNumberToObject(jsonResponse, "ret_code", RETURN_CODE_SUCCESS);
	return jsonResponse;
}

static char *return_error(const char *request, const int errCode, const char *errMsg)
{
	char *response = NULL;
	cJSON *jsonResponse = build_response(request);
	cJSON_AddNumberToObject(jsonResponse, "ret_code", errCode);
	cJSON_AddStringToObject(jsonResponse, "msg", errMsg);
	response = cJSON_Print(jsonResponse);
	cJSON_Delete(jsonResponse);
	return response;
}

/////////////////////////////////////////////handle/////////////////////////////////////////////
static char *handle_status(const char *request)
{
	cJSON *jsonResponse = return_success(request);
	char *response = cJSON_Print(jsonResponse);
	cJSON_Delete(jsonResponse);
	return response;
}

/////////////////////////////////////////////handle/////////////////////////////////////////////

static void _handle(char *request, char *response, int *size/*response size*/, SOCKET sock)
{
	char *action = (char *)malloc(128* sizeof(char));
	memset(action, 0, 128);

	get_request_action(request, action);
	if(strlen(action) == 0){
		LOG_ERROR("invalid request field [action],[%s]", request);
		return ;
	}
	if(strcmp(action, ACTION_YUNIFY_STATUS) == 0){
		char *ret = handle_status(request);
		strcpy(response, ret);
		*size = lstrlenA(response);
		if(ret != NULL){
			free(ret);
			ret = NULL;
		}
	}else {
		LOG_ERROR("invalid action[%s]!", action);
		return;
	}

	if(action != NULL){
		free(action);
		action = NULL;
	}
	return;
}

static int _request_check(const char *req)
{
	char result[32] = {0};
	char errmsg[1024] = {0};
	int ret_code = 0;

	if (get_request_action(req, result) != 0){
		LOG_ERROR("get request action error in [%s]", req);
		if(get_ret_code(req, &ret_code) != 0){
			LOG_ERROR("get ret_code error in [%s]", req);
			return -1;
		}

		if(get_errmsg(req, errmsg) !=0 ){
			LOG_ERROR("get request errmsg error in [%s]", req);
			return -1;
		}

		if(ret_code > 0){
			LOG_INFO("This is a response error message: [%s]", req);
			LOG_ERROR("The errMsg is : [%s]", errmsg);
			return ret_code;
		}
		return -1;
	}
	return 0;
}

void socket_handler(SOCKET sock, void *data)
{
	char rep[1024] = {0};
	int len = 0;
	int ret = 0;

	if((ret = _request_check((const char *)data)) < 0)
	{
		LOG_ERROR("check request format with error.");
		char *ret = return_error((const char *)data, RETURN_CODE_INVALID_REQUEST_PARAM, RETURN_MESSAGE_INVALID_REQUEST_PARAM);
		strcpy(rep, ret);
		free(ret);
		if (socket_send(sock, rep, len) < 0);
		{
			LOG_ERROR("send response [%s] error", rep);
			return;
		}
	}

	if(ret > 0){
		return;
	}

	_handle((char *)data, rep, &len, sock);
	
	if (strlen(rep) > 0)
	{
		if (socket_send(sock, rep, len) < 0)
		{
			LOG_ERROR("send response [%s] error", rep);
		}
		LOG_INFO("send Response: [%s]", rep);
	}
}
