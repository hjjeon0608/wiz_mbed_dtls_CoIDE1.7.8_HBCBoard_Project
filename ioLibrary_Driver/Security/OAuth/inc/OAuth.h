#ifndef _OAUTH_H_
#define _OAUTH_H_

#define OAUTH_VER		"1.0"
#include "OAuthDataStructure.h"
/*
 * OAuth
 * Author
 */
#define OAUTH_PARAMETER_START	"Authorization: Oauth"
#define OAUTH_CONSUMER_KEY		"oauth_consumer_key"
#define OAUTH_SIGNATURE_METHOD	"oauth_signature_method"
#define OAUTH_SIGNATURE			"oauth_signature"

void OAuthGenNonce(unsigned char *nonce,unsigned int length);/*done*/
char* OAuthCreateSignature(unsigned char *key, unsigned char* baseString);/*done*/
char* OAuthPercentEncoding(char *);/*done*/
void OAuthConcatenate(unsigned char** target, unsigned char* Str1, unsigned char* Str2);
char* OAuthMakeBaseString(OAuthDataStructure *OauthDS);
void OauthHTTP(OAuthDataStructure *OauthDS, unsigned char* httpRequest);
/*
 * normal function
 * RFC3986 encode
 * OAuthHTTPParam
 * OAuthBaseString
 * char* OAuthGenNonce(void)
 */

/*
 * callback functions
 * void GetTimeStamp(unsigned long * timeStamp);
 * void GetAlphaNumericRandom(unsigned char * ANRD);
 * void HmacSha1(const unsigned char* key,unsigned int keyLength ,const unsigned char* message, unsigned int messageLength, unsigned char* sha1_hash[20]);
 * void
 */


#endif
