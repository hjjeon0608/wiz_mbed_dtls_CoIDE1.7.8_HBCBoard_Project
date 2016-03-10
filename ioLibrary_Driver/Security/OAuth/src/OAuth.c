#include "OAuth.h"
#include "mbedtls/base64.h"
#include "HMAC_SHA_1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

char* OAuthCreateSignature(unsigned char *key, unsigned char* baseString)
{
	unsigned int writtenLength;
	unsigned char tempBuffer[100];
	unsigned char sha1Output[20];
	unsigned char * signature;
	HMAC_SHA1(key, baseString, sha1Output);
	if(mbedtls_base64_encode(tempBuffer,100,&writtenLength,sha1Output,20) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
		return 0;
	else
	{
		signature = OAuthPercentEncoding(tempBuffer);
		return signature;
	}
}

void OAuthGenNonce(unsigned char *nonce,unsigned int length)
{
	static const unsigned char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";//26+26+10 = 56
	int i;
	for(i = 0 ; i < length ; i++)
		nonce[i] = chars[rand()%62];
}

char* OAuthPercentEncoding(char *Str)
{
	size_t StrSize,NewStrSize;
	size_t Index = 0;
	int i;
	unsigned char *NewStr;
	if(Str == NULL) return 0;
	StrSize = strlen(Str);
	NewStrSize = StrSize +1;
	NewStr = (char*)malloc(StrSize);
	for(i = 0 ; i < StrSize ; i++)
	{
		switch (Str[i]) {
			case '0':case'1':case'2':case'3':case'4':case'5':case'6':case'7':case'8':case'9':
			case 'A':case 'B':case 'C':case 'D':case 'E':case 'F':case 'G':case 'H':case 'I':case 'J':
			case 'K':case 'L':case 'M':case 'N':case 'O':case 'P':case 'Q':case 'R':case 'S':case 'T':
			case 'U':case 'V':case 'W':case 'X':case 'Y':case 'Z':
			case 'a':case 'b':case 'c':case 'd':case 'e':case 'f':case 'g':case 'h':case 'i':case 'j':
			case 'k':case 'l':case 'm':case 'n':case 'o':case 'p':case 'q':case 'r':case 's':case 't':
			case 'u':case 'v':case 'w':case 'x':case 'y':case 'z':
			case '-':case '.':case '_':case '~':
				NewStr[Index++] = Str[i];
				break;
			default:
				NewStrSize +=2;
				NewStr = (char*)realloc(NewStr,NewStrSize);

				snprintf(NewStr+Index,4,"%%%02X",Str[i]);
				Index +=3;
				break;
		}
	}
	NewStr[Index]=0;
	return NewStr;
}

void OAuthConcatenate(unsigned char** target, unsigned char* Str1, unsigned char* Str2)
{
	size_t Str1Size,Str2Size;
	Str1Size = strlen(Str1);
	Str2Size = strlen(Str2);
	if(*target == Str1)
	{
		if(*target == NULL)
			*target = (char*)calloc(Str1Size+Str2Size+1,sizeof(char));
		else
			*target = (char*)realloc(*target,Str1Size+Str2Size+1);
		strcat(*target,Str2);
	}
	else if(*target != Str1 && *target == Str2)
	{
		return;
	}
	else if(*target != Str1 && *target != Str2)
	{
		*target = (char*)calloc(Str1Size+Str2Size+1,sizeof(char));
		strcat(*target,Str1);
		strcat(*target,Str2);
	}
	else
	{
		return;
	}
}

char* OAuthMakeBaseString(OAuthDataStructure *OauthDS)
{
	if(OauthDS == NULL || OauthDS->OauthList.head == NULL || OauthDS->additionalURI == NULL ||\
			OauthDS->OauthList.logicalLength == 0 | OauthDS->requestMethod == NULL) return 0;

	OauthParameter* tmpParam;
	unsigned char * baseString = 0;
	unsigned char * paramString = 0;
	unsigned char * encodedURL = 0;
	unsigned char * tmpString = 0;
	unsigned int tmpCounter = 0;

	/*http method*/
	OAuthConcatenate(&baseString,baseString,OauthDS->requestMethod);
	OAuthConcatenate(&baseString,baseString,"&");

	/*base URI*/
	tmpString = OAuthPercentEncoding(OauthDS->baseURI);
	OAuthConcatenate(&baseString,baseString,tmpString);
	free(tmpString);

	/*additional URI*/
	tmpString = OAuthPercentEncoding(OauthDS->additionalURI);
	OAuthConcatenate(&baseString,baseString,tmpString);
	free(tmpString);

	OAuthConcatenate(&baseString,baseString,"&");

	oauthQsort(OauthDS,0,OauthDS->OauthList.logicalLength-1);
	/*Parameter string*/
	while(tmpCounter != OauthDS->OauthList.logicalLength)
	{
		tmpParam = oauthGetElement(OauthDS,tmpCounter);
		OAuthConcatenate(&paramString,paramString,tmpParam->parameter);
		OAuthConcatenate(&paramString,paramString,"=");
		OAuthConcatenate(&paramString,paramString,tmpParam->value);
		tmpCounter++;
		if(tmpCounter != OauthDS->OauthList.logicalLength)
		{
			OAuthConcatenate(&paramString,paramString,"&");
		}
	}
	/*percent encoding parameter string*/
	tmpString = OAuthPercentEncoding(paramString);
	free(paramString);
	OAuthConcatenate(&baseString,baseString,tmpString);
	free(tmpString);
	return baseString;
}

void OauthHTTP(OAuthDataStructure *OauthDS,unsigned char* httpRequest)
{
	unsigned char tempBuffer[100];
	unsigned int tmpCounter = 0;
	OauthParameter* tmpParam;
	if(OauthDS == NULL || httpRequest == NULL) return;
	strcat(httpRequest,OauthDS->requestMethod);
	strcat(httpRequest," ");
	strcat(httpRequest,OauthDS->additionalURI);
	strcat(httpRequest,"?");
	strcat(httpRequest,OauthDS->requestQuery);
	strcat(httpRequest," HTTP/1.1\r\n");
	strcat(httpRequest,"Connection: Keep-Alive\r\n");
	strcat(httpRequest,"Content-length: 0\r\n");
	strcat(httpRequest,"Host: api.twitter.com\r\n");
	strcat(httpRequest,"Authorization: OAuth ");
	while(tmpCounter != OauthDS->OauthList.logicalLength)
	{
		tmpParam = oauthGetElement(OauthDS,tmpCounter);
		memset(tempBuffer,0,100);
		tmpCounter++;
		if(tmpCounter == OauthDS->OauthList.logicalLength)
		{
			sprintf(tempBuffer,"%s=\"%s\"\r\n\r\n",tmpParam->parameter,tmpParam->value);
		}
		else
		{
			sprintf(tempBuffer,"%s=\"%s\", ",tmpParam->parameter,tmpParam->value);
		}
		strcat(httpRequest,tempBuffer);
	}
}
