#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "OAuthList.h"

void list_init(list *list, int elementSize, freeFunction freeFn)
{
  assert(elementSize > 0);
  list->logicalLength = 0;
  list->elementSize = elementSize;
  list->head = list->tail = NULL;
  list->freeFn = freeFn;
}

void list_destroy(list *list)
{
  listNode *current;
  while(list->head != NULL) {
    current = list->head;
    list->head = current->next;

    if(list->freeFn) {
      list->freeFn(current->data);
    }
    else{
    	free(current->data);
    }
    free(current);
  }
}

//void list_prepend(list *list, void *element)
//{
//  listNode *node = malloc(sizeof(listNode));
//  node->data = malloc(list->elementSize);
//  memcpy(node->data, element, list->elementSize);
//
//  node->next = list->head;
//  list->head = node;
//
//  // first node?
//  if(!list->tail) {
//    list->tail = list->head;
//  }
//
//  list->logicalLength++;
//}

void list_append(list *list, void *element)
{
  listNode *node = malloc(sizeof(listNode));
  node->data = malloc(list->elementSize);
  node->next = NULL;

  memcpy(node->data, element, list->elementSize);

  if(list->logicalLength == 0) {
    list->head = list->tail = node;
  } else {
    list->tail->next = node;
    list->tail = node;
  }
  list->logicalLength++;
}

void list_for_each(list *list, listIterator iterator)
{
  assert(iterator != NULL);

  listNode *node = list->head;
  bool result = TRUE;
  while(node != NULL && result) {
    result = iterator(node->data);
    node = node->next;
  }
}

//void list_head(list *list, void *element, bool removeFromList)
//{
//  assert(list->head != NULL);
//
//  listNode *node = list->head;
//  memcpy(element, node->data, list->elementSize);
//
//  if(removeFromList) {
//    list->head = node->next;
//    list->logicalLength--;
//
//    free(node->data);
//    free(node);
//  }
//}

bool list_pos(list *list, void *element, int pos)
{
	assert(list->head != NULL);
	assert(list->logicalLength >= pos+1);
	listNode *tmpNode;
	tmpNode = list->head;
	while(pos--)
	{
		tmpNode = tmpNode->next;
		if(tmpNode == NULL) return FALSE;
	}
	memcpy(element, tmpNode->data, list->elementSize);
	return TRUE;
}

//void list_tail(list *list, void *element)
//{
//  assert(list->tail != NULL);
//  listNode *node = list->tail;
//  memcpy(element, node->data, list->elementSize);
//}

int list_size(list *list)
{
  return list->logicalLength;
}

void list_sort(list * list, listQsort qsort)
{
	assert(qsort != NULL);
	qsort(list,0,list->logicalLength-1);
}

bool list_swap(list *list, int pos1, int pos2)
{
	assert(list->logicalLength > pos1);
	assert(list->logicalLength > pos2);
	if(pos1 == pos2) return TRUE;
	listNode *tempNode;
	listNode *preNode1 = NULL;
	listNode *preNode2 = NULL;
	listNode *pos1Node = list->head;
	listNode *pos2Node = list->head;
	//Search previous Node pos1
	while(pos1--)
	{
		preNode1 = pos1Node;
		pos1Node = pos1Node->next;
	}

	//Search previous Node pos2
	while(pos2--)
	{
		preNode2 = pos2Node;
		pos2Node = pos2Node->next;
	}
	if(pos1Node == NULL || pos2Node == NULL) return FALSE;

	if(preNode1 != NULL){
		preNode1->next = pos2Node;
	}
	else {
		list->head = pos2Node;
	}

	if(preNode2 != NULL){
		preNode2->next = pos1Node;
	}
	else{
		list->head = pos1Node;
	}
	tempNode = pos2Node->next;
	pos2Node->next = pos1Node->next;
	pos1Node->next = tempNode;

	if(pos2Node->next == NULL)
		list->tail = pos2Node;
	if(pos1Node->next == NULL)
		list->tail = pos1Node;
	return TRUE;
}
