#ifndef _CFG_OP_H_
#define _CFG_OP_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SuccessRet 1;
#define FailedRet  0;

#define MAX_CFG_BUF                              512

#define CFG_OK                                   0
#define CFG_SECTION_NOT_FOUND                    -1
#define CFG_KEY_NOT_FOUND                        -2
#define CFG_ERR                                  -10
#define CFG_ERR_FILE                             -10
#define CFG_ERR_OPEN_FILE                        -10
#define CFG_ERR_CREATE_FILE                      -11
#define CFG_ERR_READ_FILE                        -12
#define CFG_ERR_WRITE_FILE                       -13
#define CFG_ERR_FILE_FORMAT                      -14
#define CFG_ERR_SYSTEM                           -20
#define CFG_ERR_SYSTEM_CALL                      -20
#define CFG_ERR_INTERNAL                         -21
#define CFG_ERR_EXCEED_BUF_SIZE                  -22

#define COPYF_OK                                 0
#define COPYF_ERR_OPEN_FILE                      -10
#define COPYF_ERR_CREATE_FILE                    -11
#define COPYF_ERR_READ_FILE                      -12
#define COPYF_ERR_WRITE_FILE                     -13

#define TXTF_OK                                  0
#define TXTF_ERR_OPEN_FILE                       -1
#define TXTF_ERR_READ_FILE                       -2
#define TXTF_ERR_WRITE_FILE                      -3
#define TXTF_ERR_DELETE_FILE                     -4
#define TXTF_ERR_NOT_FOUND                       -5

int  FileCopy(void *source_file, void *dest_file);
int  SplitSectionToNameIndex(char *section, char **name, char **index);
int  JoinNameIndexToSection(char **section, char *name, char *index);
int  ConfigGetKey(void *CFG_file, void *section, void *key, void *buf);
int  ConfigSetKey(void *CFG_file, void *section, void *key, void *buf);
int  ConfigGetSections(void *CFG_file, char *sections[]);
int  ConfigGetKeys(void *CFG_file, void *section, char *keys[]);

#ifdef __cplusplus
}
#endif

#endif /* _CFG_OP_H */
