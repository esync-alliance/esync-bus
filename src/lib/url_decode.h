#ifndef _XL4BUS_LIB_DECODE_URL_H_
#define _XL4BUS_LIB_DECODE_URL_H_

/**
 * Removes URL encoding from a string. The string is modified in place.
 * @param text text containing URL encoding to have decoded.
 */
void decode_url(char * text);

#endif