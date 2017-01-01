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

#ifndef _FC_SLAB_H_
#define _FC_SLAB_H_

#define RUN	1
#define STOP	0
#define HIGH_FR	1
#define LOW_FR	0


//FOR GARBAGE COLLECTION
#define GC_UP_THRESHOLD	600			//stop garbage collection
#define GC_LOW_THRESHOLD 100		//begin garbage collection

//FOR FLUASH THREAD
#define FLUSH_THREAD_NUM	8
#define FLUSH_START_THRESHOLD	60		//start flush operation
#define FLUSH_STOP_THRESHOLD	40		//stop flush operation
#define FLUSH_SYNC_THRESHOLD	70	//trigger sync flush operation

//PARAMETERS FOR FLUASH THREAD
pthread_mutex_t fmut[FLUSH_THREAD_NUM];
pthread_cond_t fcond[FLUSH_THREAD_NUM];
int FLUSH_STATUS[FLUSH_THREAD_NUM];

int flush_res[FLUSH_THREAD_NUM];
pthread_t flush_thread[FLUSH_THREAD_NUM];
void *flush_thread_result[FLUSH_THREAD_NUM];


struct slab {
    uint32_t  magic;     /* slab magic (const) */
    uint32_t  sid;       /* slab id */
    uint8_t   cid;       /* slab class id */
    uint8_t   unused[3]; /* unused */
    uint8_t   data[1];   /* opaque data */
};

#define SLAB_MAGIC      0xdeadbeef
#define SLAB_HDR_SIZE   offsetof(struct slab, data)
#define SLAB_MIN_SIZE   ((size_t) MB)
#define SLAB_SIZE      8 * MB
#define SLAB_MAX_SIZE   ((size_t) (512 * MB))

struct slabinfo {
    uint32_t              sid;    /* slab id (const) */
    uint32_t              addr;   /* address as slab_size offset from memory / disk base */
    TAILQ_ENTRY(slabinfo) tqe;    /* link in free q / partial q / full q */
    uint32_t              nalloc; /* # item alloced (monotonic) */
    uint32_t              nfree;  /* # item freed (monotonic) */
    uint8_t               cid;    /* class id */
    unsigned              mem:1;  /* memory? */

    float 		  valid_ratio;
    int 		  erase_count;
    int 		  access_frq;		//what's the use of this parameter
    int 		  valid_number;
};

TAILQ_HEAD(slabhinfo, slabinfo);

struct slabclass {
    uint32_t         nitem;           /* # item per slab (const) */
    size_t           size;            /* item size (const) */
    size_t           slack;           /* unusable slack space (const) */
    struct slabhinfo partial_msinfoq; /* partial slabinfo q */
};

#define SLABCLASS_MIN_ID        0
#define SLABCLASS_MAX_ID        (UCHAR_MAX - 1)
#define SLABCLASS_INVALID_ID    UCHAR_MAX
#define SLABCLASS_MAX_IDS       UCHAR_MAX

bool slab_valid_id(uint8_t cid);
size_t slab_data_size(void);
void slab_print(void);
uint8_t slab_cid(size_t size);

struct item *slab_get_item(uint8_t cid);
void slab_put_item(struct item *it);
struct item *slab_read_item(uint32_t sid, uint32_t addr);

rstatus_t slab_init(void);
void slab_deinit(void);

//FOR THE ERASE COUNT QUEUE
struct free_slab_entry *FQ_InsertSort(struct free_slab_entry *head, int num);
void FQ_disply(struct free_slab_entry *head);
int FQ_deleteHead(int channel_id);

//FOR VALID DATA RATION BASED QUEUE
void insert_channel_full_slab(int channel_id, int num);
int delete_channel_full_slab(int channel_id, int num);
int search_channel_full_slab(int channel_id);
void channel_disply(int channel_id);

//FOR THE LRU DISK SLAB QUEUE
char* find_in_LRU(int i, char *key);
void delete_from_LRU(int i, char *key);
void add_to_LRU(int i, char *key);

//FOR THE LRU MEMORY SLAB QUEUE
char* find_in_mslab_LRU(char *key);
void delete_from_mslab_LRU(char *key);
void add_to_mslab_LRU(char *key);

//FOR GARBAGE COLLECTION THREAD
void *gc_thread_function(void *arg);
void gc_thread_resume(void);

//FOR FLUSH THREAD
void flush_thread_resume(int ch);
void *flush_thread_function(void *arg);

#endif
