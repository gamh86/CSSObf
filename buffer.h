#ifndef __Buffer_h__
#define __Buffer_h__ 1

typedef struct Buffer buf_t;
typedef struct Chunk chunk_t;
buf_t *buf_new(void);
void buf_free(buf_t *);
int buf_add(buf_t *, void *, size_t);
char *buf_peek(buf_t *, size_t);
int buf_write_fd(buf_t *, int);
int buf_read_fd(buf_t *, int, size_t);
int buf_read_socket(buf_t *, int, size_t, int);
int buf_shift(buf_t *, char *, size_t);
int buf_overwrite(buf_t *, char *, char *, size_t);
int buf_collapse(buf_t *, char *, size_t);
int buf_replace(buf_t *, char *, size_t, char *);
int buf_replace_all_instances(buf_t *, char *, char *);
void buf_coalesce(buf_t *);
#ifdef DEBUG
void dump_border_data(buf_t *);
#endif

struct Chunk
{
	int magic;
	char *data;
	char *end;
	size_t dlen;
	size_t len;
	struct Chunk *next;
};

struct Buffer
{
	char *pos;
	size_t dlen; // total length of data in all chunks
	chunk_t *head;
	chunk_t *tail;
};

#endif // !defined __Buffer_h__
