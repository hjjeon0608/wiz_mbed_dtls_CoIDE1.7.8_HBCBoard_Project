/*
 * brief: HMAC SHA1 implementation using mbedtls sha1 library
 * reference: "https://en.wikipedia.org/wiki/Hash-based_message_authentication_code"
 *
 *HMAC(K,m) = H((K^opad)||H((K^ipad)||m))
 *where H is a hash function,
 *		K is a secrete key,
 *		m is the message,
 *		|| denotes concatenation,
 *		opad is the outer padding 0x5c5c5c5c...and
 *		ipad is the inner padding 0x363636...
 *
 *The following is the pseudo code of HMAC
 *
 *function hmac (key, message)
 *	if (length(key) > blocksize) then
 *		key = hash(key) // keys longer than blocksize are shortened
 *	end if
 *	if (length(key) < blocksize) then
 *		key = key || [0x00 * (blocksize - length(key))] // keys shorter than blocksize are zero-padded (where || is concatenation)
 *	end if
 *
 *	o_key_pad = [0x5c * blocksize] ^ key // Where blocksize is that of the underlying hash function
 *	i_key_pad = [0x36 * blocksize] ^ key // Where ^ is exclusive or (XOR)
 *
 *	return hash(o_key_pad || hash(i_key_pad || message)) // Where ��is concatenation
 *	end function
 *
 */
#ifndef _HMAC_SHA_1_H_
#define _HMAC_SHA_1_H_

#define OPAD	0x5C
#define IPAD	0x36

#define BLOCK_SIZE	64	//Block size is 64 when using of the following hash functions: SHA-1, MD5, RIPEMD-128/160
#define HASH_SIZE	20	//SHA1 Hash size is 160 bits = 20 bytes

void HMAC_SHA1(unsigned char* key, unsigned char* message, unsigned char* sha1_hash);

#endif
