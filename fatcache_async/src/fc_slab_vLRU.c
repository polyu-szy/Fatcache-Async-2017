/*
 * fatcache - memcache on ssd.
 * Copyright (C) 2013 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fc_core.h>
#include <eblaze-ioctl.h>
#include <myEblaze.h>
#include <string.h>
#include "uthash.h"

/*szy: used for the mutiple channel*/
struct argument
{
  int ch;
};
extern struct settings settings;

static uint32_t nfree_msinfoq;         /* # free memory slabinfo q */
static struct slabhinfo free_msinfoq;  /* free memory slabinfo q */
static uint32_t nfull_msinfoq;         /* # full memory slabinfo q */
static struct slabhinfo full_msinfoq;  /* # full memory slabinfo q */

static uint32_t nfree_dsinfoq;         /* # free disk slabinfo q */
static struct slabhinfo free_dsinfoq;  /* free disk slabinfo q */
static uint32_t nfull_dsinfoq;         /* # full disk slabinfo q */
static struct slabhinfo full_dsinfoq;  /* full disk slabinfo q */

static uint8_t nctable;                /* # class table entry */
struct slabclass *ctable;       /* table of slabclass indexed by cid */

static uint32_t nstable;               /* # slab table entry */
struct slabinfo *stable;        /* table of slabinfo indexed by sid */

static uint8_t *mstart;                /* memory slab start */
static uint8_t *mend;                  /* memory slab end */

static off_t dstart;                   /* disk start */
static off_t dend;                     /* disk end */
static int fd;                         /* disk file descriptor */

static size_t mspace;                  /* memory space */
static size_t dspace;                  /* disk space */
static uint32_t nmslab;                /* # memory slabs */
static uint32_t ndslab;                /* # disk slabs */

static uint8_t *evictbuf;              /* evict buffer */
static uint8_t *readbuf;               /* read buffer */

/* *************************************************************
**Author:szy ; Time: 23-01-2016
**Used to manage the working thread of garbage collection
****************************************************************/

int Current_FR = HIGH_FR;

/* PTHREAD_MUTEX_INITIALIZER */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /*for child thread status*/
pthread_mutex_t mut_dsq = PTHREAD_MUTEX_INITIALIZER; /*for disk slabs*/
pthread_mutex_t mut_msq = PTHREAD_MUTEX_INITIALIZER; /*for memory slabs*/
pthread_mutex_t mut_IX = PTHREAD_MUTEX_INITIALIZER; /*for item indexs*/
pthread_mutex_t mut_I = PTHREAD_MUTEX_INITIALIZER;  /*for items*/
pthread_cond_t cond =  PTHREAD_COND_INITIALIZER;  /*to trigger gc*/
int GC_STATUS = STOP;

int gc_res;
pthread_t gc_thread;
void *gc_thread_result;

/* *************************************************************
**Author:szy ; Time: 19-01-2016
**Used to maintain a erase count queue for the free disk slabs
****************************************************************/
/*******************Start*******************/

struct free_slab_entry{
	int sid;
	struct free_slab_entry *next;
};

struct free_slab_entry *channel_free_slab[Eblaze_Channel]; //for every channel, maintain a sorted queue

int channel_free_slab_num[Eblaze_Channel];


struct free_slab_entry *FQ_InsertSort(struct free_slab_entry *head, int num)
{
	struct free_slab_entry *current_entry = head;
	struct free_slab_entry *entry;
	struct slabinfo *c_sinfo, *n_sinfo;
	entry = (struct free_slab_entry *)malloc(sizeof(struct free_slab_entry));
	entry->sid = num;
	entry->next = NULL;
	if(head == NULL)	//the head
	{
		head = entry;
		return head;
	}
	c_sinfo = &stable[num];
	n_sinfo = &stable[current_entry->sid];
	while(n_sinfo->erase_count <= c_sinfo->erase_count && current_entry->next != NULL)
	{
		current_entry = current_entry->next;
		n_sinfo = &stable[current_entry->sid];
	}
	if(current_entry->next != NULL)
	{
		struct free_slab_entry *next_entry = current_entry->next;
		current_entry->next = entry;
		entry->next = next_entry;
	}
	else
	{//tail node
		current_entry->next = entry;
	}
	return head;
}

void FQ_disply(struct free_slab_entry *head)
{
	struct free_slab_entry *entry;
	entry =  head;
	while(entry != NULL)
	{
		printf("The content is: %d\n", entry->sid);
		entry = entry->next;
	}
	printf("\n");
}

int FQ_deleteHead(int channel_id)
{
	int num;
	struct free_slab_entry *tmp;
	if(channel_free_slab[channel_id] == NULL)
	{
		num = -1;
	}
	num = channel_free_slab[channel_id]->sid;
	tmp = channel_free_slab[channel_id];
	channel_free_slab[channel_id] =  channel_free_slab[channel_id]->next;
	free(tmp);
	return num;
}

/*For valid ratio based garbage collection process*/
/*******************Start*******************/
struct full_slab_entry{
	int sid;
	struct full_slab_entry *next;
};

struct full_slab_entry *channel_full_slab[Eblaze_Channel]; //for every channel, maintain a sorted queue

int channel_full_slab_num[Eblaze_Channel];

//insert the new node in the end of this queue
void insert_channel_full_slab(int channel_id, int num)
{
	struct full_slab_entry *current_entry;
	struct full_slab_entry *entry;
	entry =  (struct full_slab_entry *) malloc(sizeof(struct full_slab_entry));
	entry->sid = num;
	entry->next = NULL;
	current_entry = channel_full_slab[channel_id];
	if(current_entry == NULL)
	{
		channel_full_slab[channel_id] = entry;
		channel_full_slab[channel_id]->next =  NULL;		
	}
	else
	{
		while(current_entry->next != NULL)
		{
			current_entry = current_entry->next;
		}	
		current_entry->next = entry;
	}
}

//delete the node with data num in this queue
int delete_channel_full_slab(int channel_id, int num)
{
	struct full_slab_entry *current;
	struct full_slab_entry *temp;
	struct full_slab_entry *tmp;
	current =  channel_full_slab[channel_id];
	if(current == NULL)
	{
		printf("Delete an empety queue!\n");
		return -1;
	}
	while(current->sid != num && current->next != NULL)
	{
		temp = current;
		current = current->next;
	}
	if(current->sid == num)
	{
		if(current == channel_full_slab[channel_id])
		{
			tmp = channel_full_slab[channel_id];
			channel_full_slab[channel_id] =  channel_full_slab[channel_id]->next;
			free(tmp);
			return 0;
		}
		else
		{
			tmp = current;
			temp->next = current->next;
			free(tmp);
			return 0;
		}
	}
	else
	{
		return -1;
	}
	
}

//search the most little num in this queue
int search_channel_full_slab(int channel_id)
{
	struct full_slab_entry *current;
	struct slabinfo *c_sinfo, *n_sinfo;
	int temp, temp_next;	
	current = channel_full_slab[channel_id];
	if(current == NULL)
	{
		temp = -1;
	}
	temp = current->sid;
	while(current->next != NULL)
	{
		c_sinfo = &stable[temp];
		current = current->next;
		temp_next = current->sid;
		n_sinfo = &stable[temp_next];
		if(n_sinfo->valid_ratio < c_sinfo->valid_ratio)
		{
			temp = temp_next;
		}	
	}
	return temp;
}



void channel_disply(int channel_id)
{
	struct full_slab_entry *head;
	head = channel_full_slab[channel_id];
	while(head != NULL)
	{
		printf("The content is: %d\n", head->sid);
		head = head->next;
	}
	printf("\n");
}
/************************END**************************/

/* *************************************************************
**Author:szy ; Time: 15-01-2016
**Used to maintain a LRU queue for the full disk slabs
****************************************************************/
/*******************Start*******************/


#define LRU_MAX_SLAB_SIZE 10000


int Channel_EV_Order;		/*evict the slab on which channel, used in round-robin*/
int Channel_Alloc_Order;	/*choose the slab on which channel, used in round-robin*/
FILE *LRU_fp;

struct SlabEntry{
	char *key;
	UT_hash_handle hh;
};


struct SlabEntry *LRU_Slab[Eblaze_Channel];

char* find_in_LRU(int i, char *key)
{
    struct SlabEntry *entry;
    HASH_FIND_STR(LRU_Slab[i], key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, LRU_Slab[i], entry);
        HASH_ADD_KEYPTR(hh, LRU_Slab[i], entry->key, strlen(entry->key), entry);
        return entry->key;
    }
    return NULL;
}


void delete_from_LRU(int i, char *key)
{
    struct SlabEntry *entry;
    HASH_FIND_STR(LRU_Slab[i], key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, LRU_Slab[i], entry);
    }
}


void add_to_LRU(int i, char *key)
{
    struct SlabEntry *entry;
    struct SlabEntry *tmp_entry;
    entry = (struct SlabEntry *)malloc(sizeof(struct SlabEntry));
    entry->key = strdup(key);
    HASH_ADD_KEYPTR(hh, LRU_Slab[i], entry->key, strlen(entry->key), entry);
    
    // prune the cache to LRU_MAX_CACHE_SIZE
    if (HASH_COUNT(LRU_Slab[i]) >= LRU_MAX_SLAB_SIZE) {
        HASH_ITER(hh, LRU_Slab[i], entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, LRU_Slab[i], entry);
            free(entry->key);
            free(entry);
            break;
        }
    }
}


/*******************End*******************/




/* *************************************************************
**Author:szy ; Time: 14-02-2016
**Used to maintain a LRU queue for the full memory slabs
****************************************************************/
/*******************Start*******************/

/*To implement the background flush operation, need to create another thread*/
/**
1. trigger condition: when the number of full memory slab is more than 3/4 of the total slabs 
2. ending condition: when the number of full memory slab is less than 1/4 of the total slabs
3. working process: trigger the drain process, and then flash memory slab to disk slab
4. queue to be managed: full_memory_slab, use LRU to manage; first add to the queue; when accessed,
   put the slab in the head; when flush happens, flush into the disk
5. lock to be used
**/

#define LRU_MAX_MSLAB_SIZE 10000

struct SlabEntry *full_memory_slab;
int full_memory_slab_num;

char* find_in_mslab_LRU(char *key)
{
    struct SlabEntry *entry;
    HASH_FIND_STR(full_memory_slab, key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh, full_memory_slab, entry);
        HASH_ADD_KEYPTR(hh, full_memory_slab, entry->key, strlen(entry->key), entry);
        return entry->key;
    }
    return NULL;
}


void delete_from_mslab_LRU(char *key)
{
    struct SlabEntry *entry;
    HASH_FIND_STR(full_memory_slab, key, entry);
    if (entry) {
        // remove it (so the subsequent add will throw it on the front of the list)
        HASH_DELETE(hh,full_memory_slab, entry);
    }
}


void add_to_mslab_LRU(char *key)
{
    struct SlabEntry *entry;
    struct SlabEntry *tmp_entry;
    entry = (struct SlabEntry *)malloc(sizeof(struct SlabEntry));
    entry->key = strdup(key);
    HASH_ADD_KEYPTR(hh, full_memory_slab, entry->key, strlen(entry->key), entry);
    
    // prune the cache to LRU_MAX_CACHE_SIZE
    if (HASH_COUNT(full_memory_slab) >= LRU_MAX_MSLAB_SIZE) {
        HASH_ITER(hh, full_memory_slab, entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, full_memory_slab, entry);
            free(entry->key);
            free(entry);
            break;
        }
    }
}


/*******************End*******************/






/***
To see when evict happens
**/
int Itemx_empty_test = 1;

/*
 * Return the maximum space available for item sized chunks in a given
 * slab. Slab cannot contain more than 2^32 bytes (4G).
 */
size_t
slab_data_size(void)
{
    return settings.slab_size - SLAB_HDR_SIZE;
}

/*
 * Return true if slab class id cid is valid and within bounds, otherwise
 * return false.
 */
bool
slab_valid_id(uint8_t cid)
{
    if (cid >= SLABCLASS_MIN_ID && cid <= settings.profile_last_id) {
        return true;
    }

    return false;
}

void
slab_print(void)
{
    uint8_t cid;         /* slab class id */
    struct slabclass *c; /* slab class */

    loga("slab size %zu, slab hdr size %zu, item hdr size %zu, "
         "item chunk size %zu", settings.slab_size, SLAB_HDR_SIZE,
         ITEM_HDR_SIZE, settings.chunk_size);

    loga("index memory %zu, slab memory %zu, disk space %zu",
         0, mspace, dspace);

    for (cid = SLABCLASS_MIN_ID; cid < nctable; cid++) {
        c = &ctable[cid];
        loga("class %3"PRId8": items %7"PRIu32"  size %7zu  data %7zu  "
             "slack %7zu", cid, c->nitem, c->size, c->size - ITEM_HDR_SIZE,
             c->slack);
    }
}

/*
 * Return the cid of the slab which can store an item of a given size.
 *
 * Return SLABCLASS_INVALID_ID, for large items which cannot be stored in
 * any of the configured slabs.
 */
uint8_t
slab_cid(size_t size)
{
    uint8_t cid, imin, imax;

    ASSERT(size != 0);

    /* binary search */
    imin = SLABCLASS_MIN_ID;
    imax = nctable;
    while (imax >= imin) {
        cid = (imin + imax) / 2;
        if (size > ctable[cid].size) {
            imin = cid + 1;
        } else if (cid > SLABCLASS_MIN_ID && size <= ctable[cid - 1].size) {
            imax = cid - 1;
        } else {
            break;
        }
    }

    if (imin > imax) {
        /* size too big for any slab */
        return SLABCLASS_INVALID_ID;
    }

    return cid;
}

/*
 * Return true if all items in the slab have been allocated, else
 * return false.
 */
static bool
slab_full(struct slabinfo *sinfo)
{
    struct slabclass *c;

    ASSERT(sinfo->cid >= SLABCLASS_MIN_ID && sinfo->cid < nctable);
    c = &ctable[sinfo->cid];

    return (c->nitem == sinfo->nalloc) ? true : false;
}

/*
 * Return and optionally verify the memory slab with the given slab_size
 * offset from base mstart.
 */
static void *
slab_from_maddr(uint32_t addr, bool verify)
{
    struct slab *slab;
    off_t off;

    off = (off_t)addr * settings.slab_size;
    slab = (struct slab *)(mstart + off);
    if (verify) {
        ASSERT(mstart + off < mend);
        ASSERT(slab->magic == SLAB_MAGIC);
        ASSERT(slab->sid < nstable);
        ASSERT(stable[slab->sid].sid == slab->sid);
        ASSERT(stable[slab->sid].cid == slab->cid);
        ASSERT(stable[slab->sid].mem == 1);
    }

    return slab;
}

/*
 * Return the slab_size offset for the given disk slab from the base
 * of the disk.
 */
static off_t
slab_to_daddr(struct slabinfo *sinfo)
{
    off_t off;

    ASSERT(!sinfo->mem);

    off = dstart + ((off_t)sinfo->addr * settings.slab_size);
    ASSERT(off < dend);

    return off;
}

/*
 * Return and optionally verify the idx^th item with a given size in the
 * in given slab.
 */
static struct item *
slab_to_item(struct slab *slab, uint32_t idx, size_t size, bool verify)
{
    struct item *it;

    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(idx <= stable[slab->sid].nalloc);
    ASSERT(idx * size < settings.slab_size);

    it = (struct item *)((uint8_t *)slab->data + (idx * size));
    if (verify) {
        ASSERT(it->magic == ITEM_MAGIC);
        ASSERT(it->cid == slab->cid);
        ASSERT(it->sid == slab->sid);
    }

    return it;
}


/*****************************************************
The eviction process need to be done before disk slab
run out, otherwise, it will be in the loop of eviction
*****************************************************/

static rstatus_t
slab_evict(void)
{
    struct slabclass *c;    /* slab class */
    struct slabinfo *sinfo; /* disk slabinfo */
    struct slab *slab;      /* read slab */
    size_t size;            /* bytes to read */
    off_t off;              /* offset */
    int n;                  /* read bytes */
    uint32_t idx;           /* idx^th item */


    /***********Parameters added by SZY: begin*************/
    int LRU_Sid = 0;		/*slab id used to add into LRU queue*/
    int Channel_id;
    char *LRU_Sid_str;
    LRU_Sid_str = (char *)malloc(100 * sizeof(char));
    /***********************END***********************/


    /**************************************************************
    **Author:szy ; Time: 15-01-2016
    **Change the eviction process from FIFO to LRU
    ****************************************************************/

    /*****************Begin*******************/     
    ASSERT(!TAILQ_EMPTY(&full_dsinfoq));
    ASSERT(nfull_dsinfoq > 0);
    //choose which channel to do the garbage collection
    while(LRU_Slab[Channel_EV_Order] == NULL)
    {
	Channel_EV_Order++;
	if(Channel_EV_Order >= Eblaze_Channel)
		Channel_EV_Order = 0;
    }	


    /*szy: lock the disk slabs for gc operation*/
    pthread_mutex_lock(&mut_dsq);

    //here to choose use LRU based queue or valid_ratio based queue
    if(Current_FR == LOW_FR)
    {// the access frequency is low, then use valid data ratio based gc
	//LRU_Sid = search_channel_full_slab(Channel_EV_Order);
	//if(LRU_Sid == -1)
	//{
	  //printf("Error, all full channel are empty\n");
	  //exit(0);
        //}
    }
    else
    {// the access frequency is high, then use LRU based gc
	LRU_Sid_str = LRU_Slab[Channel_EV_Order]->key;
	LRU_Sid = atoi(LRU_Sid_str);
    }
    
    Channel_EV_Order++;
    if(Channel_EV_Order >= Eblaze_Channel)
    {
	Channel_EV_Order = 0;	
    }

   
    sinfo = &stable[LRU_Sid];

    /*printf("Erase operation. Total number %d, Valid number %d, Valid ratio %f, Access frq %d!\n", 
	(&ctable[sinfo->cid])->nitem, sinfo->valid_number, sinfo->valid_ratio, sinfo->access_frq);
    */

    Channel_id =  sinfo->addr / (Channel_Lun * Lun_Block);
    //move the slab from valid data queue
   /* if(delete_channel_full_slab(Channel_EV_Order, LRU_Sid) == -1)
    {
	printf("Error, cannot delete a slab\n");
	exit(0);	
    }*/
    //channel_full_slab_num[Channel_EV_Order]--;
    //move the slab from LRU queue
    delete_from_LRU(Channel_id, LRU_Sid_str);
    free(LRU_Sid_str);
    //move the slab from the full slab queue 
    nfull_dsinfoq--;
    TAILQ_REMOVE(&full_dsinfoq, sinfo, tqe);
    pthread_mutex_unlock(&mut_dsq);

    ASSERT(!sinfo->mem);
    ASSERT(sinfo->addr < ndslab);
  
    
    /* read the slab */
    slab = (struct slab *)evictbuf;
    size = settings.slab_size;
    off = slab_to_daddr(sinfo);

    /* *************************************************************
    **Author:szy ; Time: 12-01-2016
    **Read a slab from the disk
    ****************************************************************/
    myEblaze_read_slab(fd, slab, sinfo->addr);

    ASSERT(slab->magic == SLAB_MAGIC);
    ASSERT(slab->sid == sinfo->sid);
    ASSERT(slab->cid == sinfo->cid);
    ASSERT(slab_full(sinfo));

    /* evict all items from the slab */
    for (c = &ctable[slab->cid], idx = 0; idx < c->nitem; idx++) {
        struct item *it = slab_to_item(slab, idx, c->size, true);
        if (itemx_getx(it->hash, it->md) != NULL) {
            itemx_removex(it->hash, it->md);
	    /*****Reclaim the valid data************/
	    //item_get(it->end, it->nkey, it->cid, it->ndata, it->expiry, it->flags, it->md, it->hash);
        }
    }

    log_debug(LOG_DEBUG, "evict slab at disk (sid %"PRIu32", addr %"PRIu32")",
              sinfo->sid, sinfo->addr);

    
    /*Erase the block corrosponding to the slab number*******/
    myEblaze_erase_slab(fd, sinfo->addr);
    /*update the erased slab information*/ 
    sinfo->valid_ratio = 1;
    sinfo->erase_count++;
    sinfo->access_frq = 1;
    sinfo->valid_number = (&ctable[sinfo->cid])->nitem;
    fprintf(LRU_fp, "Erase Option, Addr: %d, count %d\n", sinfo->addr, sinfo->erase_count);
    pthread_mutex_lock(&mut_dsq);
    channel_free_slab[Channel_id] = FQ_InsertSort(channel_free_slab[Channel_id], sinfo->sid);
    channel_free_slab_num[Channel_id]++;
    /* move disk slab from full to free q */
    TAILQ_INSERT_TAIL(&free_dsinfoq, sinfo, tqe);
    nfree_dsinfoq++; 
    
    pthread_mutex_unlock(&mut_dsq);
    return FC_OK;
}

/* *************************************************************
**Author:szy ; Time: 13-01-2016
**The thread functions used by garbage collection process
****************************************************************/
void *gc_thread_function(void *arg)
{
	while(1)
	{
		pthread_mutex_lock(&mut);
		while(!GC_STATUS)
		{
			pthread_cond_wait(&cond, &mut);
		}
		pthread_mutex_unlock(&mut);		
		
		slab_evict();
		
		//printf("Erase done, the number of free slabs now is %d!\n", nfree_dsinfoq);
		if(nfree_dsinfoq >= GC_UP_THRESHOLD)
		{
			pthread_mutex_lock(&mut);
			GC_STATUS = STOP;
			pthread_mutex_unlock(&mut);

		}
	}
}


/**To resume the garbage collection process**/
void gc_thread_resume(void)
{
	if((GC_STATUS == STOP) && (nfree_dsinfoq <= GC_LOW_THRESHOLD))
	{
		pthread_mutex_lock(&mut);
		GC_STATUS = RUN;
		
		printf("==============================\n");
		printf("Garbage collection happens!\n");
		printf("==============================\n");

		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mut);
	}

}



static void
slab_swap_addr(struct slabinfo *msinfo, struct slabinfo *dsinfo)
{
    uint32_t m_addr;

    ASSERT(msinfo->mem);
    ASSERT(!dsinfo->mem);

    /* on address swap, sid and cid are left untouched */
    m_addr = msinfo->addr;

    msinfo->addr = dsinfo->addr;
    msinfo->mem = 0;
    /* *************************************************************
    **Author:szy ; Time: 19-01-2016
    **Update the parameters for valid data ratio, frq, erase count...
    ****************************************************************/
    msinfo->valid_ratio = 1;
    msinfo->erase_count = dsinfo->erase_count;
    msinfo->access_frq = 1;
    msinfo->valid_number = (&ctable[msinfo->cid])->nitem;

    dsinfo->valid_ratio = -1;
    dsinfo->erase_count = -1;
    dsinfo->access_frq = -1;
    dsinfo->valid_number = -1;

    dsinfo->addr = m_addr;
    dsinfo->mem = 1;
}

static rstatus_t
_slab_drain(void)
{
    struct slabinfo *msinfo, *dsinfo; /* memory and disk slabinfo */
    struct slab *slab;                /* slab to write */
    size_t size;                      /* bytes to write */
    off_t off;                        /* offset to write at */
    int n;                            /* written bytes */
 
    /***********Parameters added by SZY: begin*************/
    int Alloc_sid;		/*disk id alloced by a channel*/
    int LRU_Sid;		/*slab id used to add into LRU queue*/
    int Channel_id;
    char *LRU_Sid_str;
    int LRU_MSid;
    char *LRU_MSid_str;
    LRU_Sid_str = (char *)malloc(100 * sizeof(char));
    LRU_MSid_str = (char *)malloc(100 * sizeof(char));
    /***********************END***********************/

  

    ASSERT(!TAILQ_EMPTY(&full_msinfoq));
    ASSERT(nfull_msinfoq > 0);

    ASSERT(!TAILQ_EMPTY(&free_dsinfoq));
    ASSERT(nfree_dsinfoq > 0);

    /*szy: lock for the memory slab*/    
    pthread_mutex_lock(&mut_msq);
    /* get memory sinfo from full q */
    //msinfo = TAILQ_FIRST(&full_msinfoq);  
    LRU_MSid_str = full_memory_slab->key;
    LRU_MSid = atoi(LRU_MSid_str);
    msinfo = &stable[LRU_MSid];
    delete_from_mslab_LRU(LRU_MSid_str);
    free(LRU_MSid_str);
    full_memory_slab_num--;
    nfull_msinfoq--;
    TAILQ_REMOVE(&full_msinfoq, msinfo, tqe);
    pthread_mutex_unlock(&mut_msq);

    ASSERT(msinfo->mem);
    ASSERT(slab_full(msinfo));


     /* get disk sinfo from free q */
    /* *************************************************************
    **Author:szy ; Time: 19-01-2016
    **Alloc free slab according channel id
    **1. To see if there are free slab in current channel id
    **2. If there is, alloc a free slab
    **3. If there is not, channel_id++, and then go to 1 again
    **4. If the channel becomes to Eblaze_channel, change to 0
    ****************************************************************/

    while(channel_free_slab[Channel_Alloc_Order] == NULL)
    {
	Channel_Alloc_Order++;
	if(Channel_Alloc_Order >= Eblaze_Channel)
		Channel_Alloc_Order = 0;
    }	
    /*szy: lock for the disk slab*/
    pthread_mutex_lock(&mut_dsq);

    Alloc_sid = FQ_deleteHead(Channel_Alloc_Order);
    channel_free_slab_num[Channel_Alloc_Order]--;
    
    Channel_Alloc_Order++;
    

    if(Channel_Alloc_Order >= Eblaze_Channel)
    {
    	    Channel_Alloc_Order = 0;
    }
    dsinfo = &stable[Alloc_sid];

    ASSERT(!dsinfo->mem);
    nfree_dsinfoq--;
    TAILQ_REMOVE(&free_dsinfoq, dsinfo, tqe);	
    pthread_mutex_unlock(&mut_dsq);
    /* Original
    dsinfo = TAILQ_FIRST(&free_dsinfoq);
    nfree_dsinfoq--;
    TAILQ_REMOVE(&free_dsinfoq, dsinfo, tqe);
    ASSERT(!dsinfo->mem);
    End Original*/

    /* drain the memory to disk slab */
    slab = slab_from_maddr(msinfo->addr, true);
    size = settings.slab_size;
    off = slab_to_daddr(dsinfo);
    /*
    n = pwrite(fd, slab, size, off);
    if (n < size) {
        log_error("pwrite fd %d %zu bytes at offset %"PRId64" failed: %s",
                  fd, size, off, strerror(errno));
        return FC_ERROR;
    }
    */

    /* *************************************************************
    **Author:szy ; Time: 12-01-2016
    **Flush a memory slab to disk slab
    ****************************************************************/
    myEblaze_write_slab(fd, slab, dsinfo->addr);

    //printf("Slab write, Channel number %d, slab id is %d, addr number %d!\n", Channel_Alloc_Order, dsinfo->sid, dsinfo->addr);

    log_debug(LOG_DEBUG, "drain slab at memory (sid %"PRIu32" addr %"PRIu32") "
              "to disk (sid %"PRIu32" addr %"PRIu32")", msinfo->sid,
              msinfo->addr, dsinfo->sid, dsinfo->addr);

    /* swap msinfo <> dsinfo addresses */
    /*Here just changed the address, do not change the sid*/
    slab_swap_addr(msinfo, dsinfo);  

    /***************************************************************
    **Author:szy ; Time: 15-01-2016
    **Add dsinfo to LRU queue
    ****************************************************************/
    LRU_Sid = msinfo->sid;
    Channel_id = msinfo->addr / (Channel_Lun * Lun_Block);
    sprintf(LRU_Sid_str, "%d", LRU_Sid);

    pthread_mutex_lock(&mut_dsq);
    //add the slab to LRU queue
    add_to_LRU(Channel_id, LRU_Sid_str);
    free(LRU_Sid_str);

    //add the slab to valid ratio queue
    //insert_channel_full_slab(Channel_id, msinfo->sid);
    //channel_full_slab_num[Channel_id]++;

    /* move msinfo (now a disk sinfo) to full q */
    nfull_dsinfoq++;
    TAILQ_INSERT_TAIL(&full_dsinfoq, msinfo, tqe);

    pthread_mutex_unlock(&mut_dsq);
    /* move dsinfo (now a memory sinfo) to free q */
    pthread_mutex_lock(&mut_msq);
    nfree_msinfoq++;
    TAILQ_INSERT_TAIL(&free_msinfoq, dsinfo, tqe);
    pthread_mutex_unlock(&mut_msq);


    return FC_OK;
}

static rstatus_t
slab_drain(void)
{
    rstatus_t status;

    /***************************************************************
    **Author:szy ; Time: 15-01-2016
    **Change the condition to invoke eviction process
    ****************************************************************/
    if(nfree_dsinfoq > GC_LOW_THRESHOLD)	/*set the garbage collection threshold here*/
    {
	return _slab_drain();
    }
    /* Original
    if (!TAILQ_EMPTY(&free_dsinfoq)) {
        ASSERT(nfree_dsinfoq > 0);
        return _slab_drain();
    }*/
	
   if(!GC_STATUS)
   {
       	gc_thread_resume();
    }
    while(nfree_dsinfoq <= GC_LOW_THRESHOLD / 2) 
    {
	//printf("Consume slab, the slab number is %d\n", nfree_dsinfoq);
    }  
    
    status = FC_OK;
    //status = slab_evict();
    if (status != FC_OK) {
        return status;
    }

    ASSERT(!TAILQ_EMPTY(&free_dsinfoq));
    ASSERT(nfree_dsinfoq > 0);

    return _slab_drain();
}

static struct item *
_slab_get_item(uint8_t cid)
{
    struct slabclass *c;
    struct slabinfo *sinfo;
    struct slab *slab;
    struct item *it;
 
    //for the LRU memory slab queue
    char *LRU_Sid_str;
    LRU_Sid_str = (char *)malloc(100 * sizeof(char));

    ASSERT(cid >= SLABCLASS_MIN_ID && cid < nctable);
    c = &ctable[cid];
    /*szy: lock for alloc item space*/
    pthread_mutex_lock(&mut_I);
    /* allocate new item from partial slab */
    ASSERT(!TAILQ_EMPTY(&c->partial_msinfoq));
    sinfo = TAILQ_FIRST(&c->partial_msinfoq);
    ASSERT(!slab_full(sinfo));
    slab = slab_from_maddr(sinfo->addr, true);

    /* consume an item from partial slab */
    it = slab_to_item(slab, sinfo->nalloc, c->size, false);
    it->offset = (uint32_t)((uint8_t *)it - (uint8_t *)slab);
    it->sid = slab->sid;
    sinfo->nalloc++;
    pthread_mutex_unlock(&mut_I);
    if (slab_full(sinfo)) {
        /* move memory slab from partial to full q */
	/*szy: lock for memory slab space*/
	pthread_mutex_lock(&mut_msq);
        TAILQ_REMOVE(&c->partial_msinfoq, sinfo, tqe);
        nfull_msinfoq++;
        TAILQ_INSERT_TAIL(&full_msinfoq, sinfo, tqe);

	/*szy: for the LRU full memory slab queue*/
	full_memory_slab_num++;
	sprintf(LRU_Sid_str, "%d", sinfo->sid);
	add_to_mslab_LRU(LRU_Sid_str);
	pthread_mutex_unlock(&mut_msq);
    }
	free(LRU_Sid_str);
    log_debug(LOG_VERB, "get it at offset %"PRIu32" with cid %"PRIu8"",
              it->offset, it->cid);

    return it;
}

struct item *
slab_get_item(uint8_t cid)
{
    rstatus_t status;
    struct slabclass *c;
    struct slabinfo *sinfo;
    struct slab *slab;
    int ch;

    ASSERT(cid >= SLABCLASS_MIN_ID && cid < nctable);
    c = &ctable[cid];

    if (itemx_empty()) {
	printf("No enough memory space\n");
	return NULL;
	//szyadd
	/*
        status = slab_evict();
        if (status != FC_OK) {
            return NULL;
        }*/
    }

    if (!TAILQ_EMPTY(&c->partial_msinfoq)) {
        return _slab_get_item(cid);
    }
     /**szy: add the flush process here**/   
    if(full_memory_slab_num >= FLUSH_UP_THRESHOLD)
    {
	for(ch = 0; ch < FLASH_THREAD_NUM; ch++)
	{
		flush_thread_resume(ch);
	}
    }
    while(full_memory_slab_num >= FLUSH_TRIGGER_THRESHOLD)
    {
	//add a drain operation here 
	status = slab_drain();
   	if (status != FC_OK) {
        	return NULL;
    	}
	//printf("Flushing slab, the full memory slab number is %d\n", full_memory_slab_num);
    }

    if (!TAILQ_EMPTY(&free_msinfoq)) {
	/*szy: lock for memory slab space*/
	pthread_mutex_lock(&mut_msq);
        /* move memory slab from free to partial q */
        sinfo = TAILQ_FIRST(&free_msinfoq);
        ASSERT(nfree_msinfoq > 0);
        nfree_msinfoq--;
        TAILQ_REMOVE(&free_msinfoq, sinfo, tqe);
	
        /* init partial sinfo */
        TAILQ_INSERT_HEAD(&c->partial_msinfoq, sinfo, tqe);
        /* sid is already initialized by slab_init */
        /* addr is already initialized by slab_init */
        sinfo->nalloc = 0;
        sinfo->nfree = 0;
        sinfo->cid = cid;
        /* mem is already initialized by slab_init */
        ASSERT(sinfo->mem == 1);
	
        /* init slab of partial sinfo */
        slab = slab_from_maddr(sinfo->addr, false);
        slab->magic = SLAB_MAGIC;
        slab->cid = cid;
        /* unused[] is left uninitialized */
        slab->sid = sinfo->sid;
        /* data[] is initialized on-demand */
	pthread_mutex_unlock(&mut_msq);
        return _slab_get_item(cid);
    }
    else
    {
	printf("Some error happened in the flush process!\n");
	return NULL;
    }

    ASSERT(!TAILQ_EMPTY(&full_msinfoq));
    ASSERT(nfull_msinfoq > 0);

    status = FC_OK;
    if (status != FC_OK) {
        return NULL;
    }

    return slab_get_item(cid);
}

void
slab_put_item(struct item *it)
{
    log_debug(LOG_INFO, "put it '%.*s' at offset %"PRIu32" with cid %"PRIu8,
              it->nkey, item_key(it), it->offset, it->cid);
}

struct item *
slab_read_item(uint32_t sid, uint32_t addr)
{
    struct slabclass *c;    /* slab class */
    struct item *it;        /* item */
    struct slabinfo *sinfo; /* slab info */
    int n;                  /* bytes read */
    off_t off;              /* offset to read from */
    size_t size;            /* size to read */
    off_t aligned_off;      /* aligned offset to read from */
    size_t aligned_size;    /* aligned size to read */
    
    /* *************************************************************
    **Author:szy ; Time: 12-01-2016
    **Parameters used to read one slab
    ****************************************************************/
    u64 slabOffset;
    int pageNum;

    /***********Parameters added by SZY: begin*************/
    int LRU_Sid;		/*slab id used to add into LRU queue*/
    int Channel_id;
    char *LRU_Sid_str;
    LRU_Sid_str = (char *)malloc(100 * sizeof(char));
    /***********************END***********************/

    ASSERT(sid < nstable);
    ASSERT(addr < settings.slab_size);

    sinfo = &stable[sid];
    c = &ctable[sinfo->cid];
    size = settings.slab_size;
    it = NULL;

    if (sinfo->mem) {
        off = (off_t)sinfo->addr * settings.slab_size + addr;
        fc_memcpy(readbuf, mstart + off, c->size);
        it = (struct item *)readbuf;
	sprintf(LRU_Sid_str, "%d", LRU_Sid);
        find_in_mslab_LRU(LRU_Sid_str);
        free(LRU_Sid_str);
        goto done;
    }

    off = slab_to_daddr(sinfo) + addr;
    aligned_off = ROUND_DOWN(off, 512);
    aligned_size = ROUND_UP((c->size + (off - aligned_off)), 512);
    /*
    n = pread(fd, readbuf, aligned_size, aligned_off);
    if (n < aligned_size) {
        log_error("pread fd %d %zu bytes at offset %"PRIu64" failed: %s", fd,
                  aligned_size, (uint64_t)aligned_off, strerror(errno));
        return NULL;
    }
    */
    /* *************************************************************
    **Author:szy ; Time: 12-01-2016
    **Read an 4KB page which contains the kv item
    ****************************************************************/
    slabOffset = ROUND_DOWN(addr, 4096) / 4096;
    pageNum = ROUND_UP((c->size + (addr - slabOffset * 4096)), 4096) / 4096;
    //printf("Addr is %lld, Page read, offset is %lld, numer is %d!\n", addr, slabOffset, pageNum);
    myEblaze_read_pages(fd, readbuf, sinfo->addr, slabOffset, pageNum);
   // printf("Read operation sucessed!\n");  
     
    /*Add the access frequency 19-01*/
    sinfo->access_frq++;
    /****************END*******************/

    /* *************************************************************
    **Author:szy ; Time: 15-01-2016
    **Update the LRU queue, put the accessed slab to the head of the 
    **LRU queue
    ****************************************************************/
    LRU_Sid = sinfo->sid;
    Channel_id = sinfo->addr / (Channel_Lun * Lun_Block);
    sprintf(LRU_Sid_str, "%d", LRU_Sid);
    find_in_LRU(Channel_id, LRU_Sid_str); /*szy: insert the slab into the head of the LRU queue*/	
    free(LRU_Sid_str);
    it = (struct item *)(readbuf + (addr - slabOffset * 4096));

done:
    ASSERT(it->magic == ITEM_MAGIC);
    ASSERT(it->cid == sinfo->cid);
    ASSERT(it->sid == sinfo->sid);

    return it;
}



/* *************************************************************
**Author:szy ; Time: 14-02-2016
**The thread functions used by slab flush process
****************************************************************/
void *flush_thread_function(void *arg)
{
	struct argument *arg_thread; 
	int ch;
  	arg_thread = (struct argument *)arg;
	ch = arg_thread->ch;
	while(1)
	{
		pthread_mutex_lock(&fmut[ch]);
		while(!FLUSH_STATUS[ch])
		{
			pthread_cond_wait(&fcond[ch], &fmut[ch]);
		}
		pthread_mutex_unlock(&fmut[ch]);		
		
		slab_drain();
		
		//printf("Erase done, the number of free slabs now is %d!\n", nfree_dsinfoq);
		if(full_memory_slab_num <= FLUSH_LOW_THRESHOLD)
		{
			pthread_mutex_lock(&fmut[ch]);
			FLUSH_STATUS[ch] = STOP;
			printf("Flashing slab thread %d stopped!\n", ch);
			pthread_mutex_unlock(&fmut[ch]);

		}
	}
}


/**To resume the garbage collection process**/
void flush_thread_resume(int ch)
{
	if((FLUSH_STATUS[ch] == STOP) && (full_memory_slab_num >= FLUSH_LOW_THRESHOLD))
	{
		pthread_mutex_lock(&fmut[ch]);
		FLUSH_STATUS[ch] = RUN;
		
		printf("==============================\n");
		printf("Memory slab flush happens %d!\n", ch);
		printf("==============================\n");

		pthread_cond_signal(&fcond[ch]);
		pthread_mutex_unlock(&fmut[ch]);
	}

}
/*======================END========================*/

static rstatus_t
slab_init_ctable(void)
{
    struct slabclass *c;
    uint8_t cid;
    size_t *profile;

    ASSERT(settings.profile_last_id <= SLABCLASS_MAX_ID);

    profile = settings.profile;
    nctable = settings.profile_last_id + 1;
    ctable = fc_alloc(sizeof(*ctable) * nctable);
    if (ctable == NULL) {
        return FC_ENOMEM;
    }

    for (cid = SLABCLASS_MIN_ID; cid < nctable; cid++) {
        c = &ctable[cid];
        c->nitem = slab_data_size() / profile[cid];
        c->size = profile[cid];
        c->slack = slab_data_size() - (c->nitem * c->size);
        TAILQ_INIT(&c->partial_msinfoq);
    }

    return FC_OK;
}

static void
slab_deinit_ctable(void)
{
}

static rstatus_t
slab_init_stable(void)
{
    struct slabinfo *sinfo;
    uint32_t i, j;
    uint32_t channel_id;  /*The channel_id of the slab*/
    int start_addr;	//used to serve mutiple instances --szy--31-01

    nstable = nmslab + ndslab;
    stable = fc_alloc(sizeof(*stable) * nstable);
    if (stable == NULL) {
        return FC_ENOMEM;
    }

   start_addr = settings.server_id * ndslab;

    /* init memory slabinfo q  */
    for (i = 0; i < nmslab; i++) {
        sinfo = &stable[i];

        sinfo->sid = i;
        sinfo->addr = i;
        sinfo->nalloc = 0;
        sinfo->nfree = 0;
        sinfo->cid = SLABCLASS_INVALID_ID;
        sinfo->mem = 1;
	/* *************************************************************
        **Author:szy ; Time: 19-01-2016
        **Init the valid data ratio and erase count for memory slab
	**Just set to -1
        ****************************************************************/
	sinfo->valid_ratio = -1;
	sinfo->erase_count = -1;
	sinfo->access_frq = -1;
	sinfo->valid_number = -1;
	/****************END*******************/	
	
        nfree_msinfoq++;
        TAILQ_INSERT_TAIL(&free_msinfoq, sinfo, tqe);
    }
    /* init disk slabinfo q */
    for (j = 0; j < ndslab && i < nstable; i++, j++) {
        sinfo = &stable[i];

        sinfo->sid = i;			/*slab id, start from the memory slabs*/
        sinfo->addr = j + start_addr;		/*disk slab start from j*/
        sinfo->nalloc = 0;
        sinfo->nfree = 0;
        sinfo->cid = SLABCLASS_INVALID_ID;
        sinfo->mem = 0;
	/* ****************************************************************************
        **Author:szy ; Time: 15-01-2016
        **Init the valid data ratio and erase count for memory slab
	**1.Set the valid ratio to 1; See free as valid
	**2.Set the valid item number to 0, initialize this value when allocating this slab
	**3.Set the erase_count to 0, caculate the erase count during working process
	**4.Set access frequency to 1, increase the frequency for every read/write operation
        ****************************************************************************/
	sinfo->valid_ratio = 1;
	sinfo->valid_number = 0;
	sinfo->erase_count = 0;
	sinfo->access_frq = 1;

	/*Insert the slab to the free slab of its corrosponding channel*/
	channel_id = (j + start_addr) / (Channel_Lun * Lun_Block);	
	//printf("Here is ok! %d\n", channel_id);
	/*Insert the slab id into the queue*/
	channel_free_slab[channel_id] = FQ_InsertSort(channel_free_slab[channel_id], i);
	channel_free_slab_num[channel_id]++;
	/****************END*******************/

        nfree_dsinfoq++;
        TAILQ_INSERT_TAIL(&free_dsinfoq, sinfo, tqe);
    }
    return FC_OK;
}

static void
slab_deinit_stable(void)
{
}

rstatus_t
slab_init(void)
{
    rstatus_t status;
    size_t size;
    uint32_t ndchunk;
    int ch;

   struct argument arg[FLASH_THREAD_NUM];
   /********Init the thread locks********/
   if(pthread_mutex_init(&mut, NULL) != 0)
   {
    	printf("Mutex init error!\n");
   }
   if(pthread_mutex_init(&mut_dsq, NULL) != 0)
   {
    	printf("Mutex init error!\n");
   }

   if(pthread_mutex_init(&mut_msq, NULL) != 0)
   {
    	printf("Mutex init error!\n");
   }

   if(pthread_mutex_init(&mut_IX, NULL) != 0)
   {
    	printf("Mutex init error!\n");
   }

   if(pthread_mutex_init(&mut_I, NULL) != 0)
   {
    	printf("Mutex init error!\n");
   }

   if(pthread_cond_init(&cond, NULL) != 0)
   {
   	printf("cond init error!\n");
   }


   for(ch = 0; ch < FLASH_THREAD_NUM; ch++)
   {
	//fmut[ch] = PTHREAD_MUTEX_INITIALIZER; /*for child thread status*/
	//fcond[ch] =  PTHREAD_COND_INITIALIZER;  /*to trigger gc*/
	if(pthread_mutex_init(&fmut[ch], NULL) != 0)
  	{
    		printf("FMutex init error!\n");
   	}

  	if(pthread_cond_init(&fcond[ch], NULL) != 0)
   	{
   		printf("fcond init error!\n");
    	}
	FLUSH_STATUS[ch] = STOP; 
	arg[ch].ch = ch;
	flush_res[ch] = pthread_create(&flush_thread[ch], NULL, flush_thread_function, (void *)&arg[ch]);
	if(flush_res[ch] != 0)
	{
		printf("Slab flush thread create error\n");
   	}
   }
  
   gc_res = pthread_create(&gc_thread, NULL, gc_thread_function, NULL);
   if(gc_res != 0)
   {
   	printf("Garbge collection thread create error\n");
   }
   GC_STATUS = STOP;
  
 
   
    /****Init the LRU queue******/
    int m;
    Channel_EV_Order = 0;			//used to control the eviction process, channel number
    Channel_Alloc_Order = 0;			//used to control the alloc process, channel number
    for(m = 0; m < Eblaze_Channel; m++)
    {
 	LRU_Slab[m] = NULL;
	channel_free_slab[m] = NULL;
	channel_free_slab_num[m] = 0;
 	//channel_full_slab[m] = NULL;
	//channel_full_slab_num[m] = 0;
    }    
    full_memory_slab = NULL;
    full_memory_slab_num = 0;
    LRU_fp = fopen("HitRatio.txt", "w+");
    if (LRU_fp == NULL) {
        printf("Init, Failed to open the file to store the LRU information\n");
        return FC_ERROR;
    }


    nfree_msinfoq = 0;
    TAILQ_INIT(&free_msinfoq);
    nfull_msinfoq = 0;
    TAILQ_INIT(&full_msinfoq);

    nfree_dsinfoq = 0;
    TAILQ_INIT(&free_dsinfoq);
    nfull_dsinfoq = 0;
    TAILQ_INIT(&full_dsinfoq);

    nctable = 0;
    ctable = NULL;

    nstable = 0;
    stable = NULL;

    mstart = NULL;
    mend = NULL;

    dstart = 0;
    dend = 0;
    fd = -1;

    mspace = 0;
    dspace = 0;
    nmslab = 0;
    ndslab = 0;

    evictbuf = NULL;
    readbuf = NULL;

    if (settings.ssd_device == NULL) {
        log_error("ssd device file must be specified");
        return FC_ERROR;
    }

    /* init slab class table */
    status = slab_init_ctable();
    if (status != FC_OK) {
        return status;
    }

    /* init nmslab, mstart and mend */
    nmslab = MAX(nctable, settings.max_slab_memory / settings.slab_size);
    //add the memory space:szy
    //nmslab =  (1024 * MB)  / settings.slab_size;
    mspace = nmslab * settings.slab_size;
    mstart = fc_mmap(mspace);
    if (mstart == NULL) {
        log_error("mmap %zu bytes failed: %s", mspace, strerror(errno));
        return FC_ENOMEM;
    }
    mend = mstart + mspace;


     /* init disk descriptor */
    /* *************************************************************
    **Author:szy ; Time: 08-01-2016
    **Init disk descriptor, open the char device /dev/memcon
    ****************************************************************/
    //fd = open(settings.ssd_device, O_RDWR | O_DIRECT, 0644);
    fd = open("/dev/memcona", O_RDWR);
    if (fd < 0) {
        log_error("open '%s' failed: %s", settings.ssd_device, strerror(errno));
        return FC_ERROR;
    }
 
    /* *************************************************************
    **Author:szy ; Time: 12-01-2016
    **Init nslab, return the size of the char device 
    ****************************************************************/

    /* init ndslab, dstart and dend */
    /*status = fc_device_size(settings.ssd_device, &size);
    if (status != FC_OK) {
        return status;
    }*/
    size = myEblaze_size(fd);
    printf("V1, The size of the device file is %lu\n", size);

    ndchunk = size / settings.slab_size;
    ASSERT(settings.server_n <= ndchunk);
    ndslab = ndchunk / settings.server_n;
    dspace = ndslab * settings.slab_size;
    dstart = (settings.server_id * ndslab) * settings.slab_size;
    dend = ((settings.server_id + 1) * ndslab) * settings.slab_size;


    printf("Memory slab %d, Disk slab %d\n", nmslab, ndslab);
    /* init slab table */
    status = slab_init_stable();
    if (status != FC_OK) {
        return status;
    }

    /* init evictbuf and readbuf */
    evictbuf = fc_mmap(settings.slab_size);
    if (evictbuf == NULL) {
        log_error("mmap %zu bytes failed: %s", settings.slab_size,
                  strerror(errno));
        return FC_ENOMEM;
    }
    memset(evictbuf, 0xff, settings.slab_size);

    readbuf = fc_mmap(settings.slab_size);
    if (readbuf == NULL) {
        log_error("mmap %zu bytes failed: %s", settings.slab_size,
                  strerror(errno));
        return FC_ENOMEM;
    }
    memset(readbuf, 0xff, settings.slab_size);

    return FC_OK;
}

void
slab_deinit(void)
{
    slab_deinit_ctable();
    slab_deinit_stable();
}
