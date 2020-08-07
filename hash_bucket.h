#ifndef __HASH_BUCKET_H__
#define __HASH_BUCKET_H__ 1

#include <stdint.h>
#include <sys/types.h>

#define LOAD_FACTOR(bo) \
(float)((float)(bo)->nr_buckets_used / (float)(bo)->nr_buckets)

#define BUCKET_CALLBACKS_SIZE 32
typedef struct Bucket_Object bucket_obj_t;
typedef struct Bucket bucket_t;

typedef void(*BUCKET_cb_t)(bucket_t *);

struct Bucket
{
	char *key;
	uint32_t hash; // the hash of the key
	void *data;
	size_t data_len;
	int used;
	struct Bucket *next; // linked list of collisions
};

struct Bucket_Object
{
	bucket_t *buckets;
	unsigned int nr_buckets;
	unsigned int nr_buckets_used;
	float load_factor;
	BUCKET_cb_t callbacks[BUCKET_CALLBACKS_SIZE];
	unsigned int nr_callbacks;
};

#define BUCKET_FL_NO_FREE 0x01
#define BUCKET_FL_NO_COPY 0x02

bucket_obj_t *BUCKET_object_new(void);
void BUCKET_object_destroy(bucket_obj_t *bObj, int flags);
int BUCKET_put_data(bucket_obj_t *bObj, char *key, void *data, size_t len, int flags);
//int BUCKET_put_data_no_copy(bucket_obj_t *bObj, char *key, void *data);
int BUCKET_reset_buckets(bucket_obj_t *bObj, int flags);
void BUCKET_clear_bucket(bucket_obj_t *bObj, char *key, int flags);
bucket_t *BUCKET_get_bucket(bucket_obj_t *bObj, char *key);
bucket_t *BUCKET_get_bucket_from_list(bucket_t *bucket, char *key);
bucket_t *BUCKET_get_list_bucket_for_value(bucket_t *bucket, void *data, size_t data_len);
char *BUCKET_get_key_for_value(bucket_t *bucket, void *data, size_t data_len);
void BUCKET_dump_all(bucket_obj_t *);

void BUCKET_register_callback(bucket_obj_t *bObj, BUCKET_cb_t cb);

#endif /* !defined __HASH_BUCKET_H__ */
