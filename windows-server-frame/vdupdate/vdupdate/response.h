#ifndef _HANDLE_ACTION_H__
#define _HANDLE_ACTION_H__

#define ACTION_YUNIFY_STATUS "status"

#define RETURN_CODE_SUCCESS 0
#define RETURN_CODE_UNKNOWN_FAILED 1
#define RETURN_CODE_INVALID_REQUEST_PARAM 1000
#define RETURN_CODE_INTERNAL_ERROR 5000

#define RETURN_MESSAGE_SUCCESS "succeed"
#define RETURN_MESSAGE_UNKNOWN_FAILED "unknown error"
#define RETURN_MESSAGE_INVALID_REQUEST_PARAM "invalid request parameter"
#define RETURN_MESSAGE_INTERNAL_ERROR "internal error!"

void socket_handler(SOCKET sock, void *data);

#endif
