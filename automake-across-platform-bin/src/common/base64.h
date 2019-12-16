#ifndef _BASE64_H__
#define _BASE64_H__

unsigned char *base64_encode(const unsigned char *str, int length);
unsigned char *base64_decode(unsigned char *str, int strict, int *retlen);

#endif