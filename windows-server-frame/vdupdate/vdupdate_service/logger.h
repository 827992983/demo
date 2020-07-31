/*
   Copyright (C) 2009 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LOGGER_H__
#define _LOGGER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
	#include <windows.h>
	#define PID GetCurrentProcessId()
	#define TID GetCurrentThreadId()
#endif

#ifdef __GNUC__
	#include <sys/types.h>
	#include <unistd.h>
	#include <pthread.h>
	#define PID getpid()
	#define TID pthread_self()
#endif

#define MAX_LOG_FILE_SIZE (100*1024*1024)

extern unsigned int log_level;
enum {
  LEVEL_DEBUG,
  LEVEL_WARN,
  LEVEL_ERROR
};

void log_init(const char *log_file);
void log_write(unsigned int type,const char *file, const char *function, const int line, const char *format, ...);
void log_cleanup(void);

#define LOG(type, format, ...) log_write(type, __FILE__, __FUNCTION__, __LINE__, format, ## __VA_ARGS__)

#define LOG_DEBUG(format, ...) LOG(LEVEL_DEBUG, format, ## __VA_ARGS__)
#define LOG_WARN(format, ...) LOG(LEVEL_WARN, format, ## __VA_ARGS__)
#define LOG_ERROR(format, ...) LOG(LEVEL_ERROR, format, ## __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // _LOGGER_H__
