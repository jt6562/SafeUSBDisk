/*
  * ============================================================================
  *
  *       Filename:  sms4.h
  *
  *    Description:  Public interface for the SMS4 encryption algorithm.
  *
  *        Version:  1.0
  *        Created:  2012年04月01日 15时18分14秒
  *       Revision:  none
  *       Compiler:  gcc
  *
  *         Author:  Long, longcpp9@gmail.com
  *        Company:  SDU
  *
  * ============================================================================
 */
#include<stdint.h>

#ifndef SMS4_INCLUDED
#define SMS4_INCLUDED
#define SMS4_BLOCK_SIZE 16
void sms4_calc_round_key(uint32_t const *key, uint32_t *round_key);
void sms4_encrypt(void *plaintext, uint32_t const *key);
void sms4_decrypt(void *ciphertext, uint32_t const *key);

#endif /* SMS4_INCLUDED */
