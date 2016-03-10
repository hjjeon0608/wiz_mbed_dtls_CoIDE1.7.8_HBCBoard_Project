#include "HMAC_SHA_1.h"
#include "mbedtls/sha1.h"

static unsigned char SHA1HashOutput[HASH_SIZE];
static mbedtls_sha1_context SHA1Context;
static unsigned char keyBuffer[BLOCK_SIZE],o_key_pad[BLOCK_SIZE],i_key_pad[BLOCK_SIZE];

void HMAC_SHA1(unsigned char* key, unsigned char* message, unsigned char* sha1_hash)
{
	int i;
	memset(keyBuffer,0,BLOCK_SIZE);
	memset(o_key_pad,0,BLOCK_SIZE);
	memset(i_key_pad,0,BLOCK_SIZE);
	memset(SHA1HashOutput,0,HASH_SIZE);

	if(strlen(key)>BLOCK_SIZE)
	{
		mbedtls_sha1_init(&SHA1Context);
		mbedtls_sha1_starts(&SHA1Context);
		mbedtls_sha1_update(&SHA1Context,key,strlen(key));
		mbedtls_sha1_finish(&SHA1Context,SHA1HashOutput);
		memcpy(keyBuffer,SHA1HashOutput,HASH_SIZE);
	}
	else
	{
		memcpy(keyBuffer,key,strlen(key));
	}

	/*inner padding*/
	mbedtls_sha1_init( &SHA1Context );
	mbedtls_sha1_starts( &SHA1Context );
	for(i = 0 ; i < BLOCK_SIZE ; i++)
	{
		o_key_pad[i] = keyBuffer[i] ^ 0x5C;
		i_key_pad[i] = keyBuffer[i] ^ 0x36;
	}
	mbedtls_sha1_update(&SHA1Context,i_key_pad,BLOCK_SIZE);
	mbedtls_sha1_update(&SHA1Context,message,strlen(message));
	mbedtls_sha1_finish(&SHA1Context,SHA1HashOutput);

	/*outer padding*/
	mbedtls_sha1_init(&SHA1Context);
	mbedtls_sha1_starts(&SHA1Context);
	mbedtls_sha1_update(&SHA1Context,o_key_pad,BLOCK_SIZE);
	mbedtls_sha1_update(&SHA1Context,SHA1HashOutput,HASH_SIZE);
	memset(SHA1HashOutput,0,HASH_SIZE);
	mbedtls_sha1_finish(&SHA1Context,SHA1HashOutput);
	mbedtls_sha1_free(&SHA1Context);

	/*hash finishing*/
	memcpy(sha1_hash,SHA1HashOutput,HASH_SIZE);
}
