/**
 * Construct chunkitems Hashtable implementation 
 **/
#include "chunkhash.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <cmath>

#define XID_TYPE "CID"
/**
 * Construct a new ptr to newitem in hash table
 * @param cname - chunkitem key
 * @param cpath - chunkitem storage path
 * @return chunkhash item
 **/
chunkhash_item* create_item(char* cname, char* cpath)
{
    chunkhash_item* c_item = (chunkhash_item*) malloc (sizeof(chunkhash_item));
    c_item->cname = (char*) malloc (strlen(cname) + 1);
    c_item->cpath = ( char*) malloc (strlen(cpath) + 1);

    strcpy(c_item->cname, cname);
    strcpy(c_item->cpath, cpath);
    c_item->next=NULL;
    return c_item;
}

/**
 * Help functions
 * de-allocate memory for an item or hashtable pointer
 **/
void releaseItem(chunkhash_item* item) {
   free(item->cname);
    free(item->cpath);
    item->next=NULL;
    free(item);
}

void releaseTable(chunkhash_table* table) {
    for (int i=0; i<table->size; i++) {
        chunkhash_item* item = table->items[i];
        if (item != NULL)
            releaseItem(item);
    }
    free(table->items);
    free(table);
}

/**
 * Hash table initialization
 **/
chunkhash_table* create_table(int tableSize)
{
    //create a new chunkhash table
    chunkhash_table* table = (chunkhash_table*)malloc(sizeof(chunkhash_table));
    table->size = tableSize;
    table->count=0;
    table->items = (chunkhash_item**)calloc(table->size, sizeof(chunkhash_item*));
    for (int i=0; i<table->size; i++)
    	table->items[i]=NULL;
    return table;
}

/**
 * Hash function
 **/
unsigned int cHash(char* str)
{
	uint64_t hash = 0xDEADBEEF;
	std::string chunkKey(str);
	std::string cType =XID_TYPE;
	cType += ":";

	//handle ncid_sign. only use the signature part since that's uniquie
	std::size_t ncid_found = chunkKey.find("::");
	std::size_t found = chunkKey.find(cType);
	std::string chunkDataKey;

	if (ncid_found != std::string::npos) {
		 cout <<" Check NCID existing in string "<< ncid_found << endl;
                cout <<" rest of the signature string "<< chunkKey.substr(ncid_found+2) <<endl;
		chunkDataKey = chunkKey.substr(ncid_found+2) ;
	} else if (found != std::string::npos) {
		cout <<" Check CID existing in string "<< found << endl;
		cout <<" rest of the string "<< chunkKey.substr(found + cType.length()) <<endl;
		chunkDataKey = chunkKey.substr(found + cType.length());
	} else {
		chunkDataKey = chunkKey;
	}
	size_t sum=0;
        size_t index=0;
            for (int i = 0; i < chunkDataKey.length(); i++) {

	        hash ^= chunkDataKey[i];
       		hash ^= ((hash << 31) ^ (hash >> 17));

                sum += (hash * (int)pow(31, i)) % (int)TABLE_SIZE;
	    }
            	index =sum % (int)TABLE_SIZE;
	    return index;
        }

/**
 * Insert the chunk items in hashtable
 * @param chunkhash table - hashtable of chunkitems
 * @param cname - chunkitemKey eg CID
 * @return VOID
 **/
void AddItem(chunkhash_table* table, char* cname, char* cpath)
{
	//compute an index for chunkitem
	int index = cHash(cname);
	chunkhash_item* item = create_item(cname, cpath);
	
	//Ptr to the first item for the index
        chunkhash_item* chunkPtr = table->items[index];

	if (chunkPtr == NULL)
	     {
		  //chunkItem key does not exist in table
		if(table->count == table->size){
			//hash table size full
		std::cout << cname << " failed to insert due to hash table is full!" <<endl;
		releaseItem(item);
		return;
		  	}
		//add item in the front of list
		table->items[index]= item;
		std::cout << cname << " has been added in hash table successfully!" <<endl;
		table->count++;
	     } else {
		     std::cout <<" get into loop having ptr already "<< endl;

	             if (strcmp(chunkPtr->cname, cname) == 0) {
			     strcpy(table->items[index]->cpath, cpath);
			     std::cout << cname << " has been updated to new path " << cpath  <<endl;
                	 return;
                    } else {
			    //handle collision to add in the last of the linkedlist
			    std::cout<< "collision occurs, add into linked list" <<endl;
			
			    while (chunkPtr->next != NULL){
				    chunkPtr = chunkPtr->next;
			    }
			    chunkPtr->next=item;
			    table->count++;
			    return;
		    }
		 }
} 

/**
 * Print out chunkitem hashtable
 **/
void printTable(chunkhash_table* table) {
    cout << "print chunk hashtable containing of total chunkitems : "<< table->count << endl;
    for (int i=0; i<table->size; i++) {
	printChunkitems(table, i);
        }
   
}

/**
 * Retrieve the chunk items in the index
 * @param chunkhash table - hashtable of chunkitems
 * @param cname - chunkitemKey eg CID
 * @return cpath - chunkitem storage path, NULL if not found in hashtable
 **/
char* LookupChunk(chunkhash_table* table, char* cname)
{
    // Locate chunkName in the hashtable
    int index = cHash(cname);
    bool foundItem = false;

    //ptr to firstItem for the index
    chunkhash_item* item = table->items[index];

    // Ensure that we move to a non NULL item
    while (item != NULL)
    	{ 
	   if (strcmp(item->cname, cname) == 0)
		{
		    foundItem = true; 
	    	    std::cout << "Found match " << cname << " 's path " << item->cpath << endl;
	    	    return item->cpath;
		}
	   item = item->next;
    	}
    if (foundItem == false) {
		    return NULL;
		}
}
	

/**
 * Check if chunk items exists in the hash table
 * @param chunkhash table - hashtable of chunkitems
 * @param cname - chunkitemKey eg CID
 * @return VOID
 **/
void print_lookup(chunkhash_table* table, char* cname) {
    char* cpath;
    if ((cpath = LookupChunk(table, cname)) == NULL) {
        cout << cname << " was not found in hash table." << endl;
        return;
    }
    else {
	    std::cout << cname << " was found in hash table! " <<endl;
    }
}

/**
 * Help function
 * Retrieve the chunk items via the table index
 **/
void printChunkitems(chunkhash_table* table, unsigned int index){
	//first item in my index
	int numOfitem =0;
	chunkhash_item* item = table->items[index];
	if (item != NULL){
		numOfitem++;
		if (item->next == NULL)
		{
		 cout << "index: " << index <<" only contains the item " << item->cname << endl;
		 return;
		}
	  cout << "index {" << index << "} contains chunk item: "<<endl;
		while (item->next  != NULL) {
			cout <<"item " << item->cname << endl;
			item = item->next;
			numOfitem++;
		}
		//also print out the last item
		cout << "item " << item->cname << endl;
	  cout << "total items in the index " << numOfitem << endl;
	  return;
	}
}
/**
 * Remove the chunk items from hash table
 * @param chunkhash_table  hash table holding chunk items
 * @parm cname chunk item key 
 * @return null if the item doesn't exist in table, otherwise ptr of the deleted item
 **/
void RemoveItem(chunkhash_table* table, char* cname)
{
        int itemDel =1;
        int index = cHash(cname);
	int bfound=0;

	chunkhash_item* rmPtr;
	chunkhash_item* tmpPtr;
	chunkhash_item* nextPtr;

//index only contain one item and match my key
	if (table->items[index] == NULL){
		std::cout << cname << " doesn't exist in hashtable. "<< endl;
                return;
	}
	// case of index contain chunk items
	else if ( strcmp(table->items[index]->cname, cname) == 0 && table->items[index]->next == NULL) {
			//delete the chunk item storage
			 //also using the item path to delete the item from storage
                        itemDel = remove(table->items[index]->cpath);
			bfound = 1;
			//delete the pointer
			      chunkhash_item *tmp = table->items[index];
			      table->items[index] = NULL;
                              std::cout << cname << " has been removed from hashtable! " <<endl;
                              delete tmp;
         } else if (strcmp(table->items[index]->cname, cname) == 0 ){
		bfound = 1;
		rmPtr = table->items[index];

		//handle storage deletion
		itemDel = remove(rmPtr->cpath);
		table->items[index] = table->items[index]->next;
		delete rmPtr;

		std::cout << cname << " has been removed from hashtable collision index " <<endl;

	 	} else {
			nextPtr = table->items[index]->next;
			tmpPtr = table->items[index];

			while( nextPtr != NULL && strcmp(nextPtr->cname, cname) != 0){
				tmpPtr = nextPtr;
				nextPtr = nextPtr->next;
			}
		 	if(nextPtr == NULL)
		 	{
		   	cout << cname << " was not found in the hashtable collision either!"<< endl;
		 	} else {
			 //found match
			 bfound = 1;
			 cout << "Get in the middle loop of collision" <<endl;

			 //handle storage deletion and then hashptr deletion
                	 itemDel = remove(nextPtr->cpath);

			 rmPtr = nextPtr;
			 nextPtr= nextPtr->next;
			 tmpPtr->next= nextPtr;
			 delete rmPtr;
			 cout << cname << " was removed in hash table collision index"<< endl;
		 	}
	 	}
	//print out storage deletion message
	if (bfound == 1)
	{
		table->count--;
		if (itemDel == 0){
      			cout<< cname << " has been deleted from Xcache storage too!" << endl;
        	} else {
                	cout << cname << " failed to delete from Xcache storage. " << endl;
		}
	}
	return;

}