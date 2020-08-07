#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "buffer.h"
#include "cssobf.h"
#include "hash_bucket.h"

#define CLASS_CHAR '.'
#define ID_CHAR '#'
#define clear_struct(s) memset((s), 0, sizeof((*s)))

#define IS_VALID_CHAR(c) \
	isalpha((c)) || \
	(c) == '_' || \
	(c) == '-'

static struct stat statb;
static bucket_obj_t *bObj = NULL;

static void
__attribute__((constructor)) __cssobf_init(void)
{
	srand(time(NULL));
}

int
file_check(char *file)
{
	assert(file);
	char *p = file + strlen(file);
	while (*p != '.' && p > (file+1))
		--p;

	if (p == file)
		return 0;
	++p;
	if (strncmp(p, "css", 3))
		return 0;

	if (access(file, F_OK) != 0)
		return 0;
	if (access(file, R_OK) != 0)
		return 0;

	clear_struct(&statb);
	assert(lstat(file, &statb) == 0);
	return S_ISREG(statb.st_mode);
}

char *
read_file(char *file, size_t *len)
{
	assert(file);

	int fd = -1;
	char *contents = NULL;

	assert((fd = open(file, O_RDONLY)) > 0);
	assert((contents = calloc(statb.st_size+1, 1)) != NULL);

	size_t toread = statb.st_size;
	ssize_t n;
	char *p = contents;

	while (toread && (n = read(fd, p, toread)))
	{
		if (0 > n)
		{
			if (errno == EINTR)
				continue;
			else
				goto fail;
		}

		p += n;
		toread -= n;
	}

	contents[statb.st_size] = 0;
	*len = statb.st_size;
	return contents;

fail:
	return NULL;
}

/**
 * Create obfuscated classnames/ids and put them
 * in global hash bucket (bObj) as classname/id (key)
 * obfuscated name (value) pairs.
 */
buf_t *
css_hash_classes(char *file)
{
	if (!file_check(file))
		return NULL;

	bObj = BUCKET_object_new();
	buf_t *buf = buf_new();
	buf_read_fd(buf, open(file, O_RDONLY), statb.st_size);
	buf_coalesce(buf);

	char *s;
	char *p = buf->head->data;
	char *e = buf->head->data + buf->dlen;
	chunk_t *ch = buf->head;
	static char key[512];
	static char name[64];
	short n = rand();
	size_t diff;
	int ok = 0;

	while (1)
	{
		if ((*p == CLASS_CHAR || *p == ID_CHAR))
		{
			if (p > buf->head->data)
			{
				char c = *(p-1);
				if (c == '\n' || c == '\t')
					ok = 1;
			}
			else
				ok = 1;

			if (ok)
			{
				++p;
				s = p;

				while (IS_VALID_CHAR(*p))
					++p;

				strncpy(key, s, p - s);
				key[p - s] = 0;

				size_t len1 = p - s;
				size_t len2;
				int longer;
				size_t diff;

				char *nm = NULL;
				bucket_t *b = BUCKET_get_bucket(bObj, key);
				if (!b)
				{
					sprintf(name, "_%hx", n);
					++n;
					BUCKET_put_data(bObj, key, (void *)name, strlen(name), 0);
#ifdef DEBUG
					fprintf(stderr, "Stored \"%s\" with value \"%s\"\n", key, name);
#endif
				}
#ifdef DEBUG
				else
				{
					fprintf(stderr, "Already got key value pair in hash bucket\n");
				}
#endif

				nm = b ? (char *)b->data : name;
				len2 = b ? b->data_len : strlen(name);
				longer = len2 > len1;

				//fprintf(stderr, "Hash: \"%s\" => \"%s\"\n", key, name);
				if (longer)
				{
					diff = len2 - len1;
					buf_shift(buf, s, diff);
					buf_overwrite(buf, s, nm, len2);
				}
				else
				{
					diff = len1 - len2;
					buf_collapse(buf, s+len2, diff);
					buf_overwrite(buf, s, nm, len2);
				}
			}

			ok = 0;
		}

		++p;
		if (p >= ch->end)
		{
			ch = ch->next;
			if (!ch)
				break;
			p = ch->data;
		}
	}

	return buf;
fail:
	if (buf)
		buf_free(buf);
	return NULL;
}

char *
file_append_extension(char *f, char *ext)
{
	assert(f);
	assert(ext);

	char *res = calloc(strlen(f) + strlen(ext) + 1, 1);
	assert(res);
	strcpy(res, f);
	res = strcat(res, ext);

	return res;
}

int
obfuscate_files_in_dir(char *dir)
{
	DIR *dhandle;
	struct dirent *dent;
	static char path[1024];

	assert(bObj);
	assert(dir);

	strcpy(path, dir);
	char *p = path + strlen(dir);
	buf_t *buf = NULL;
	int fd = -1;
	struct stat st;
	*p++ = 0x2f;

	assert(NULL != (dhandle = fdopendir(open(dir, O_DIRECTORY))));
	while ((dent = readdir(dhandle)))
	{
		if (!strcmp(dent->d_name, ".") ||
			!strcmp(dent->d_name, "..") ||
			dent->d_name[0] == '.')
			continue;

		strcpy(p, dent->d_name);
		assert(-1 != (fd = open(path, O_RDONLY)));
		clear_struct(&st);
		assert(lstat(path, &st) == 0);
		buf = buf_new();
		buf_read_fd(buf, fd, st.st_size);
		buf_coalesce(buf);
		close(fd);

		int j;
		for (j = 0; j < bObj->nr_buckets; ++j)
		{
			bucket_t *b = &bObj->buckets[j];
			if (b->used)
				buf_replace_all_instances(buf, b->key, (char *)b->data);
		}

		char *fout = file_append_extension(path, ".obf");
		assert(fout);
		assert(-1 != (fd = open(fout, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR)));
		buf_write_fd(buf, fd);
		close(fd);
		buf_free(buf);
	}

	return 0;
}

int
css_obfuscate(char *file, char *dir)
{
	if (!file_check(file))
		return -1;

	buf_t *buf = css_hash_classes(file);
	assert(buf);

	char *css_out = file_append_extension(file, ".obf");
	assert(css_out);

	fprintf(stderr, "Creating %s\n", css_out);
	int fd2 = open(css_out, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	buf_write_fd(buf, fd2);
	buf_free(buf);
	free(css_out);

	obfuscate_files_in_dir(dir);

	return 0;
}
