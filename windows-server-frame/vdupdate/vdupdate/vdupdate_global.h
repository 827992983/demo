#ifndef VDUPDATE_GROBAL_H
#define VDUPDATE_GROBAL_H

#define DEBUG

//#define IS_SERVICE

#define DEFAULT_LOG_DIR_PATH  "C:\\Windows\\Temp\\QingCloud\\logs"
#define DEFAULT_LOG_FILE_PATH "C:\\Windows\\Temp\\QingCloud\\logs\\vdupdate.log"
#define SERVICE_LOG_PATH     "C:\\Windows\\Temp\\QingCloud\\logs\\vdupdate_service.log"

#define AGENT_STOP_EVENT   TEXT("Global\\vdupdate_stop_event")

/* vdhost server info */
#define VDHOST_SERVER_IP "127.0.0.1"
#define VDHOST_SERVER_PORT 9710

#endif // ! VDUPDATE_GROBAL_H

