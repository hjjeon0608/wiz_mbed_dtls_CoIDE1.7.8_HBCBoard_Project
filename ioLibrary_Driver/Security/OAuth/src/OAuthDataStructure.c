#include "OAuthDataStructure.h"
#include "assert.h"
#include <stdio.h>

void oauth_init(OAuthDataStructure *OauthDS)
{
	OauthDS->baseURI = NULL;
	OauthDS->requestMethod = NULL;
	OauthDS->additionalURI = NULL;
	OauthDS->requestQuery = NULL;
	list_init(&(OauthDS->OauthList),sizeof(OauthParameter),oauthElementfree);
}

void oauth_setBaseURL(OAuthDataStructure *OauthDS, unsigned char* baseURL)
{
	OauthDS->baseURI = baseURL;
}
void oauth_setRequestQuery(OAuthDataStructure *OauthDS, unsigned char* requestQuery)
{
	OauthDS->requestQuery = requestQuery;
}

void oauth_setRequestMethod(OAuthDataStructure *OauthDS, unsigned char* method)
{
	OauthDS->requestMethod = method;
}

void oauth_setRequestURI(OAuthDataStructure *OauthDS, unsigned char* additionalURI)
{
	OauthDS->additionalURI = additionalURI;
}

void oauthElementfree(void *element)
{
	free((OauthParameter *)element);
}

char* oauthGetParameter(OAuthDataStructure *OauthDS,int pos)
{
	assert(OauthDS->OauthList.head != NULL);
	assert(OauthDS->OauthList.logicalLength >= pos+1);
	listNode *tmpNode = OauthDS->OauthList.head;
	OauthParameter *nodedata;
	while(pos--)
	{
		tmpNode = tmpNode->next;
	}
	nodedata = (OauthParameter*)tmpNode->data;
	return nodedata->parameter;
}

char* oauthGetValue(OAuthDataStructure *OauthDS, int pos)
{
	assert(OauthDS->OauthList.head != NULL);
	assert(OauthDS->OauthList.logicalLength >= pos+1);
	listNode *tmpNode = OauthDS->OauthList.head;
	OauthParameter *nodedata;
	while(pos--)
	{
		tmpNode = tmpNode->next;
	}
	nodedata = (OauthParameter*)tmpNode->data;
	return nodedata->value;
}

OauthParameter* oauthGetElement(OAuthDataStructure *OauthDS, int pos)
{
	assert(OauthDS->OauthList.head != NULL);
	assert(OauthDS->OauthList.logicalLength >= pos+1);
	listNode *tmpNode = OauthDS->OauthList.head;
	OauthParameter *nodedata;
	while(pos--)
	{
		tmpNode = tmpNode->next;
	}

	return (OauthParameter*)tmpNode->data;
}
void oauthAddParameter(OAuthDataStructure *OauthDS, char * param, char * value)
{
	OauthParameter nodedata;
	nodedata.parameter = param;
	nodedata.value = value;
	list_append(&(OauthDS->OauthList),&nodedata);
}

bool oauthIterate_string(void *data)
{
	OauthParameter *param;
	param = (OauthParameter *)data;
	printf("Param: %s\r\n",param->parameter);
	printf("Value: %s\r\n",param->value);
	return TRUE;
}

void oauthQsort(OAuthDataStructure *OauthDS, unsigned int left, unsigned int right)
{
	assert(OauthDS->OauthList.head != NULL || OauthDS->OauthList.logicalLength >= left + 1 || OauthDS->OauthList.logicalLength >= right + 1);
	unsigned int pivot, tmpLeft, tmpRight;
	tmpLeft = left;
	tmpRight = right;
	pivot = left;
	while(left < right)
	{
		while((strcmp(oauthGetParameter(OauthDS,right),oauthGetParameter(OauthDS,pivot)) >= 0) && (left < right))
		{
			right--;
		}
		while((strcmp(oauthGetParameter(OauthDS,left),oauthGetParameter(OauthDS,pivot))  <= 0) && (left < right))
		{
			left++;
		}
		if(left != right)
		{
			list_swap(&(OauthDS->OauthList),left,right);
			right--;
		}
	}
	list_swap(&(OauthDS->OauthList),left,pivot);
	pivot = left;
	left = tmpLeft;
	right = tmpRight;

	if(left < pivot)
		oauthQsort(OauthDS,left,pivot -1);
	if(right > pivot)
		oauthQsort(OauthDS,pivot+1,right);
}
