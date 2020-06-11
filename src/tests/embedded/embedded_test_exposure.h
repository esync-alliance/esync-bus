
// this header exposes functions that are normally defined static inside the library.
// this way the test code can call them.

#ifndef _EMBEDDED_TEST_EXPOSURE_H_
#define _EMBEDDED_TEST_EXPOSURE_H_

int e_test_is_mint_incoming(message_internal_t *mint);

#endif