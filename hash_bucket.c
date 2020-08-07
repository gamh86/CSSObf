#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hash_bucket.h"

//#define HASHING_PRIME 1610612741u
#define ALIGN_SIZE(s) (((s) + 0xf) & ~(0xf))

#define BUCKET(h, n) ((h)%(n))
#define DEFAULT_NUMBER_BUCKETS 256
#define DEFAULT_LOAD_FACTOR_THRESHOLD 0.75f

#define NR_CALLBACKS(o) ((o)->nr_callbacks)
#define CALLBACKS(o) ((o)->callbacks)

static void
Log(char *fmt, ...)
{
#ifdef DEBUG
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
#else
	(void)fmt;
#endif

	return;
}

/*
static void
rotate_byte_left(char *c, int amount)
{
	unsigned char uc = (unsigned char)*c;

	if (amount == sizeof(c))
		return;

	uc = ((uc << amount) | (uc >> (sizeof(c) - amount)));
	*c = (char)uc;

	return;
}
*/

#define GOLDEN_RATIO32 2654435769u
static uint32_t
hash_Object(char *data)
{
	assert(data);

	size_t len = strlen(data);
	uint64_t rax = 0;
	unsigned char *p = (unsigned char *)data;
	unsigned char *e = (unsigned char *)data + len;

	while (p < e)
	{
		rax ^= ((uint32_t)*p * GOLDEN_RATIO32) >> 24;
		++p;
	}

	return (uint32_t)rax;
}

static void
free_bucket_list(bucket_t *list_start, BUCKET_cb_t *funcs, unsigned int nr_cbs)
{
	bucket_t *current;
	bucket_t *prev;

	current = list_start;

	while (current)
	{
		prev = current;
		current = current->next;

		if (nr_cbs)
		{
			int j;

			for (j = 0; j < nr_cbs; ++j)
				funcs[j](prev);
		}

		free(prev);
	}

	return;
}

static void
free_buckets(bucket_obj_t *bucket_obj, int flags)
{
	assert(bucket_obj);

	int i;
	unsigned nr_buckets = bucket_obj->nr_buckets;
	bucket_t *bucket;

	for (i = 0; (unsigned int)i < nr_buckets; ++i)
	{
		bucket = &bucket_obj->buckets[i];

		if (bucket->used)
		{
			if (bucket->next != NULL)
			{
				Log("Freeing linked list of buckets from bucket #%d\n", i);
				free_bucket_list(bucket->next, CALLBACKS(bucket_obj), NR_CALLBACKS(bucket_obj));
			}

		/*
		 * Call all registered callbacks for this bucket object.
		 */
			if (NR_CALLBACKS(bucket_obj) > 0)
			{
				int j;
				int nr = NR_CALLBACKS(bucket_obj);

				for (j = 0; j < nr; ++j)
					CALLBACKS(bucket_obj)[j](bucket);
			}

			if (!(flags & BUCKET_FL_NO_FREE))
			{
				Log("Freeing data at bucket #%d\n", i);
				free(bucket->data);
			}

			bucket->data_len = 0;
			bucket->used = 0;
			bucket->next = NULL;

			--bucket_obj->nr_buckets_used;
		}
	}

	free(bucket_obj->buckets);
}

/**
 * After increasing the number of buckets, we need
 * to move the buckets around because HASH % NR_BUCKETS
 * will give a different index, which means we wouldn't
 * be able to retrieve our data.
 */
static int
adjust_buckets(bucket_obj_t *bucket_obj, int flags)
{
	assert(bucket_obj);

	bucket_t *old_bucket;
	bucket_t *buckets;
	bucket_obj_t tmp_bucket_obj;
	unsigned int i;
	unsigned int nr_buckets = bucket_obj->nr_buckets;

	buckets = calloc(nr_buckets, sizeof(bucket_t));
	memset(buckets, 0, sizeof(bucket_t) * nr_buckets);

	tmp_bucket_obj.buckets = buckets;
	tmp_bucket_obj.nr_buckets = nr_buckets;
	tmp_bucket_obj.nr_buckets_used = 0;
	tmp_bucket_obj.load_factor = bucket_obj->load_factor;
	tmp_bucket_obj.nr_callbacks = 0;

	Log("Adjusting buckets after increasing number of buckets\n");

	for (i = 0; i < nr_buckets; ++i)
	{
		old_bucket = &bucket_obj->buckets[i];
		if (BUCKET_put_data(&tmp_bucket_obj,
				old_bucket->key,
				old_bucket->data,
				old_bucket->data_len,
				flags) < 0)
		{
			Log("adjust_buckets: failed to put data into new bucket array\n");
			goto fail;
		}
	}

/*
 * Free the data, linked lists, etc, from the
 * old buckets array and point to the newly
 * created one.
 */
	free_buckets(bucket_obj, flags);

	bucket_obj->buckets = buckets;
	bucket_obj->nr_buckets_used = tmp_bucket_obj.nr_buckets_used;

	memset(&tmp_bucket_obj, 0, sizeof(bucket_obj_t));

	Log("New bucket array at %p\n", bucket_obj->buckets);
	return 0;

fail:
	free_buckets(&tmp_bucket_obj, 0);
	free_buckets(bucket_obj, flags);
	buckets = NULL;
	bucket_obj->buckets = NULL;

	return -1;
}

/**
 * Check if we have passed the load factor
 * threshold and double the number of
 * buckets if so.
 */
static void
check_load_factor(bucket_obj_t *bucket_obj, int flags)
{
	float load_factor = LOAD_FACTOR(bucket_obj);

	if (load_factor >= bucket_obj->load_factor)
	{
		Log("Resizing bucket array (load factor: %f)\n", load_factor);

		bucket_obj->nr_buckets <<= 1;
		bucket_obj->buckets = realloc(bucket_obj->buckets, (bucket_obj->nr_buckets*sizeof(bucket_t)));
		assert(bucket_obj->buckets);

		Log("Number of buckets now %u\n", bucket_obj->nr_buckets);

		if (adjust_buckets(bucket_obj, flags) < 0)
			abort(); // XXX Handle this more elegantly
	}

	return;
}

static bucket_t *
new_bucket(void)
{
	bucket_t *bucket = malloc(sizeof(bucket_t));

	if (!bucket)
		return NULL;

	bucket->data = NULL;
	bucket->data_len = 0;
	bucket->used = 0;
	bucket->next = NULL;

	return bucket;
}

void
BUCKET_dump_all(bucket_obj_t *bucket_obj)
{
	assert(bucket_obj);

	bucket_t *bucket = &bucket_obj->buckets[0];
	int i, j;
	for (i = 0, j = bucket_obj->nr_buckets; i < j; ++i)
	{
		bucket = &bucket_obj->buckets[i];
		if (!bucket->used)
			continue;
		assert(bucket->key);
		assert(bucket->data);

		fprintf(stderr, "Bucket #%d: key == %s, value == %s\n",
				i, (char *)bucket->key, (char *)bucket->data);
	}

	return;
}

int
BUCKET_put_data(bucket_obj_t *bucket_obj, char *key, void *data, size_t data_len, int flags)
{
	assert(bucket_obj);
	assert(key);
	assert(data);

	uint32_t hash = hash_Object(key);
	int index = BUCKET(hash, bucket_obj->nr_buckets);
	size_t key_len = strlen(key);
	bucket_t *bucket;

	Log("Hash of key \"%s\": %X\n", key, hash);
	Log("Bucket index: %d\n", index);

	bucket = &bucket_obj->buckets[index];

	if (bucket->used)
	{
		while (bucket->next != NULL)
			bucket = bucket->next;

		bucket->next = new_bucket();
		bucket = bucket->next;
	}
	else
	{
		++bucket_obj->nr_buckets_used;
	}

	bucket->key = calloc(ALIGN_SIZE(key_len), 1);

	if (!bucket->key)
		goto fail;

	memcpy((void *)bucket->key, (void *)key, key_len);

	bucket->key[key_len] = 0;
	bucket->hash = hash;

	if (flags & BUCKET_FL_NO_COPY)
	{
		bucket->data = data;
		bucket->data_len = data_len;
	}
	else
	{
		bucket->data = calloc(ALIGN_SIZE(data_len), 1);
		if (!bucket->data)
			goto fail;
		memcpy(bucket->data, data, data_len);
		bucket->data_len = data_len;
	}

	bucket->used = 1;

	Log("%s => %s\n", key, (char *)bucket->data);

	check_load_factor(bucket_obj, flags);

	return 0;

fail:
	if (bucket->key)
		free(bucket->key);

	if (!(flags & BUCKET_FL_NO_FREE))
	{
		if (bucket->data)
			free(bucket->data);
		bucket->data = NULL;
	}

	return -1;
}

bucket_t *
BUCKET_get_bucket(bucket_obj_t *bucket_obj, char *key)
{
	assert(key);

	uint32_t hash = hash_Object(key);

	Log("got hash of %s: %X\n", key, hash);
	int index = BUCKET(hash, bucket_obj->nr_buckets);
	bucket_t *bucket = &bucket_obj->buckets[index];

	if (bucket->used)
		return bucket;
	else
		return NULL;
}

bucket_t *
BUCKET_get_bucket_from_list(bucket_t *bucket, char *key)
{
	assert(bucket);
	assert(key);

	size_t key_len = strlen(key);

	while (bucket)
	{
		if (!memcmp((void *)bucket->key, (void *)key, key_len))
			return bucket;

		bucket = bucket->next;
	}

	return NULL;
}

bucket_t *
BUCKET_get_list_bucket_for_value(bucket_t *bucket, void *data, size_t data_len)
{
	assert(bucket);
	assert(data);

	if (!data_len)
		return NULL;

	while (bucket)
	{
		if (!memcmp(data, bucket->data, data_len))
			return bucket;

		bucket = bucket->next;
	}

	return NULL;
}

char *
BUCKET_get_key_for_value(bucket_t *bucket, void *data, size_t data_len)
{
	assert(bucket);
	assert(data);

	if (!data_len)
		return NULL;

	while (bucket)
	{
		if (!memcmp(data, bucket->data, data_len))
			return bucket->key;

		bucket = bucket->next;
	}

	return NULL;
}

bucket_obj_t *
BUCKET_object_new(void)
{
	bucket_obj_t *bucket_obj = malloc(sizeof(bucket_obj_t));

	if (!bucket_obj)
		return NULL;

	bucket_obj->buckets = calloc(DEFAULT_NUMBER_BUCKETS, sizeof(bucket_t));

	if (!bucket_obj->buckets)
		goto fail_release_bucket_obj;

	bucket_obj->nr_buckets = DEFAULT_NUMBER_BUCKETS;
	bucket_obj->nr_buckets_used = 0;
	bucket_obj->load_factor = DEFAULT_LOAD_FACTOR_THRESHOLD;

	memset(bucket_obj->buckets, 0, sizeof(bucket_t) * DEFAULT_NUMBER_BUCKETS);

	return bucket_obj;

fail_release_bucket_obj:

	free(bucket_obj);
	return NULL;
}

void
BUCKET_object_destroy(bucket_obj_t *bucket_obj, int flags)
{
	if (!bucket_obj)
		return;

	free_buckets(bucket_obj, flags);
	free(bucket_obj);

	return;
}

/**
 * Free all buckets and data and create
 * a new bucket array with default
 * number of buckets.
 */
int
BUCKET_reset_buckets(bucket_obj_t *bucket_obj, int flags)
{
	assert(bucket_obj);

	free_buckets(bucket_obj, flags);

	bucket_obj->nr_buckets = DEFAULT_NUMBER_BUCKETS;
	bucket_obj->nr_buckets_used = 0;
	bucket_obj->buckets = calloc(DEFAULT_NUMBER_BUCKETS, sizeof(bucket_t));

	if (!bucket_obj->buckets)
		return -1;

	return 0;
}

void
BUCKET_clear_bucket(bucket_obj_t *bucket_obj, char *key, int flags)
{
	assert(bucket_obj);
	assert(key);

	bucket_t *bucket = BUCKET_get_bucket(bucket_obj, key);
	if (!bucket)
		return;

	if (bucket->next)
	{
		free_bucket_list(bucket->next, CALLBACKS(bucket_obj), NR_CALLBACKS(bucket_obj));
		bucket->next = NULL;
	}

	if (NR_CALLBACKS(bucket_obj))
	{
		int j;
		int nr = NR_CALLBACKS(bucket_obj);

		for (j = 0; j < nr; ++j)
			CALLBACKS(bucket_obj)[j](bucket);
	}

	free(bucket->key);
	bucket->key = NULL;

	if (!(flags & BUCKET_FL_NO_FREE))
	{
		free(bucket->data);
		bucket->data = NULL;
	}

	bucket->data_len = 0;
	bucket->hash = 0;
	bucket->used = 0;

	--bucket_obj->nr_buckets_used;

	return;
}

void
BUCKET_register_callback(bucket_obj_t *bucket_obj, BUCKET_cb_t cb)
{
	CALLBACKS(bucket_obj)[NR_CALLBACKS(bucket_obj)] = cb;
	++NR_CALLBACKS(bucket_obj);

	return;
}
