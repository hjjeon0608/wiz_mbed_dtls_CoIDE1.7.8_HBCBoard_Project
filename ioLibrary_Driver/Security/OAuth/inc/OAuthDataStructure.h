#ifndef _OAUTHDATASTRUCTURE_H_
#define _OAUTHDATASTRUCTURE_H_

#include "oauthlist.h"

typedef struct{
	char* parameter;
	char* value;
}OauthParameter;

typedef struct _OAuthDataStructure{
	unsigned char* baseURI;
	unsigned char* requestMethod;
	unsigned char* additionalURI;
	unsigned char* requestQuery;
	list OauthList;
}OAuthDataStructure;

void oauth_init(OAuthDataStructure *);
void oauth_setRequestMethod(OAuthDataStructure *OauthDS, unsigned char* method);
void oauth_setRequestURI(OAuthDataStructure *, unsigned char* additionalURI);
void oauth_setBaseURL(OAuthDataStructure *, unsigned char* baseURL);
void oauth_setRequestQuery(OAuthDataStructure *, unsigned char* query);

/*Linked list related function*/
void oauthElementfree(void *element);
char* oauthGetParameter(OAuthDataStructure *OauthDS,int pos);
char* oauthGetValue(OAuthDataStructure *OauthDS, int pos);
OauthParameter* oauthGetElement(OAuthDataStructure *OauthDS, int pos);
void oauthAddParameter(OAuthDataStructure *OauthDS, char * param, char * value);
bool oauthIterate_string(void *data);
void oauthQsort(OAuthDataStructure *OauthDS, unsigned int left, unsigned int right);

#endif
