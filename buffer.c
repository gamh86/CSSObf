/*
 * A buffer implementation using a linked list of chunks of
 * memory. The main reason for writing this implementation is
 * to avoid ever using a realloc() which invalidates any active
 * pointers to areas of the buffer.
 *
 * Written by Gary Hannah, 2020.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"

typedef struct Match
{
	char *s;
	char *e;
	chunk_t *ch1;
	chunk_t *ch2;
	int straddles;
} match_t;

static chunk_t *new_chunk(void);
static chunk_t *new_chunk_with_size(size_t);
static void free_chunk(chunk_t *);

#define _MAGIC 0xdeadbeef

#define perr(m) fprintf(stderr, "%s: %s (%s)\n", __func__, (m), strerror(errno))
#define DEFAULT_BUFSIZE 1024

#define _USED(c) ((c)->dlen)
#define _AVAILABLE(c) ((c)->len - _USED(c))
#define _CHUNK_SIZE(c) ((c)->len)
#define DATA_END(c) ((c)->data + (c)->dlen)
#define IS_IN_CHUNK(p,c) ((p) >= (c)->data && (p) < (c)->end)
#define DLEN_ADD(ch,i) \
do { \
	assert(0 <= (i) && (i) <= _AVAILABLE(ch)); \
	assert(((ch)->dlen + (i)) <= (ch)->len); \
	(ch)->dlen += (i); \
} while (0)

#define DLEN_SUB(ch,i) \
do { \
	assert(0 <= (i) && (i) <= (ch)->dlen); \
	assert(((ch)->data + ((ch)->dlen - (i))) >= (ch)->data); \
	(ch)->dlen -= (i); \
} while (0)

#ifdef DEBUG
# define BUF_ASSERT(b) \
do { \
	assert((b)); \
	assert((b)->head); \
	assert((b)->head->data); \
	assert((b)->tail); \
} while (0)

# define CHUNK_ASSERT(c) \
do { \
	assert((c)); \
	assert((c)->magic == _MAGIC); \
	assert((c)->data); \
	assert((c)->dlen <= (c)->len && 0 <= (c)->dlen); \
	assert((c)->next != (c)); \
} while (0)
#else
# define BUF_ASSERT(b)
# define CHUNK_ASSERT(c)
#endif

#ifdef DEBUG
# define PRN(p, l) \
do { \
	int __i__; \
	fputc(0x0a,stderr); \
	for (__i__ = 0; __i__ < (int)(l); ++__i__) \
		fprintf(stderr, "%02hhx", *(p+__i__)); \
	fputc(0x0a,stderr); \
	for (__i__ = 0; __i__ < (int)(l); ++__i__) \
		fputc(*(p+__i__), stderr); \
	fputc(0x0a,stderr); \
} while (0)
#else
# define PRN(p, l)
#endif

static void
DBG(char *fmt, ...)
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

static void
_add_chunk(buf_t *buf, chunk_t *ch)
{
	assert(buf);
	assert(ch);
	if (NULL == buf->tail)
		buf->tail = buf->head = ch;
	else
	{
		buf->tail->next = ch;
		buf->tail = ch;
	}

	return;
}

/**
 * Find the chunk in the buffer where POS belongs.
 */
static chunk_t *
_get_chunk_for_pos(buf_t *buf, char *pos)
{
	chunk_t *ch;

	for (ch = buf->head; ch; ch = ch->next)
	{
		if (IS_IN_CHUNK(pos,ch))
			return ch;
	}

	return NULL;
}

/**
 * Create a new buffer which has one chunk of memory
 * with default number of bytes.
 */
buf_t *
buf_new(void)
{
	buf_t *b = malloc(sizeof(struct Buffer));
	if (NULL == b)
		goto fail;

	b->dlen = 0;
	b->tail = new_chunk();
	assert(b->tail);
	b->head = b->tail;
	assert(NULL == b->head->next);
	b->pos = b->head->data;
	return b;
fail:
	perr("Failed to allocate memory for new buffer");
	return NULL;
}

/**
 * Free a buffer.
 *
 * @param buf The buffer
 */
void
buf_free(buf_t *buf)
{
	assert(buf);

	chunk_t *pr;
	chunk_t *ch;

	for (pr = buf->head, ch = buf->head->next; pr; ch = ch->next)
	{
		//DBG("Freeing chunk at address %p\n", pr);
		free_chunk(pr);
		pr = ch;
		if (NULL == ch)
			break;
	}

	return;
}

/**
 * Return a chunk of memory to the operating system.
 *
 * @param ch The chunk to free.
 */
void
free_chunk(chunk_t *ch)
{
	free(ch->data);
	free(ch);

	return;
}

/**
 * Allocate a new chunk of memory from the heap
 * with a determined size.
 *
 * @param size The size of the chunk to be allocated.
 */
chunk_t *
new_chunk_with_size(size_t size)
{
	size_t alloc_size = size+16;
	chunk_t *ch = malloc(sizeof(chunk_t));
	if (NULL == ch)
		return NULL;
	ch->data = calloc(alloc_size, 1);
	if (NULL == ch->data)
	{
		free(ch);
		return NULL;
	}

	ch->magic = _MAGIC;
	ch->len = alloc_size;
	ch->dlen = 0;
	ch->end = ch->data + alloc_size;
	ch->next = NULL;
	memset(ch->data, 0, alloc_size);

	return ch;
}

/**
 * Allocate a new chunk of memory from the heap
 * with a default number of bytes.
 */
chunk_t *
new_chunk(void)
{
	chunk_t *ch = malloc(sizeof(chunk_t));
	if (NULL == ch)
		return NULL;
	ch->data = calloc(DEFAULT_BUFSIZE, 1);
	if (NULL == ch->data)
	{
		free(ch);
		return NULL;
	}

	ch->magic = _MAGIC;
	ch->dlen = 0;
	ch->len = DEFAULT_BUFSIZE;
	ch->end = ch->data + DEFAULT_BUFSIZE;
	ch->next = NULL;
	memset(ch->data, 0, DEFAULT_BUFSIZE);

	return ch;
}

static int
_read_fd(int fd, char *p, size_t size)
{
	ssize_t n;
	size_t r = size;

	while (r && (n = read(fd, p, r)))
	{
		if (n < 0)
		{
			if (EINTR == errno)
				continue;
			else
				goto fail;
		}

		p += n;
		r -= n;
	}

	return (int)size;

fail:
	return -1;
}

/**
 * Read a determined number of bytes from a socket.
 *
 * @param sock The socket from which to read.
 * @param p The pointer to the receiving buffer.
 * @param size The number of bytes to read.
 * @param flags Flags to pass to recv()
 */
static int
_read_socket(int sock, char *p, size_t size, int flags)
{
	ssize_t n;
	size_t r = size;

	while (r && (n = recv(sock, p, r, flags)))
	{
		if (n < 0)
		{
			if (EINTR == errno || EAGAIN == errno || EWOULDBLOCK == errno)
				continue;
			else
				goto fail;
		}

		p += n;
		r -= n;
	}

	return (int)size;

fail:
	return -1;
}

/**
 * Read content from a socket into the buffer
 *
 * @param buf The buffer
 * @param sock The file descriptor for the socket
 * @param len Number of bytes to read from file
 * @param flags Flags to pass to recv()
 */
int
buf_read_socket(buf_t *buf, int sock, size_t len, int flags)
{
	assert(buf);
	assert(buf->head);
	assert(buf->head->data);
	assert(2 < sock);
	assert(buf->pos >= buf->head->data && buf->pos < buf->head->end);

	chunk_t *ch = buf->head;
	size_t avail = _AVAILABLE(ch);
	int retval;
	if (avail > len)
	{
		retval = _read_socket(sock, buf->pos, len, flags);
		assert(0 < retval);

		buf->pos += len;
		DLEN_ADD(ch,len);
	}
	else
	{
		retval = _read_socket(sock, buf->pos, avail, flags);
		assert(0 < retval);

		buf->pos += avail;
		DLEN_ADD(ch,avail);

		chunk_t *nch = new_chunk_with_size((len - avail) + 1);
		ch->next = buf->tail = nch;
		buf->pos = nch->data;

		size_t r = (len - avail);
		retval = _read_socket(sock, buf->pos, r, flags);
		assert(0 < retval);

		DLEN_ADD(nch,r);
	}

	buf->dlen += len;
	return len;
}

/**
 * Read content from a file descriptor into the buffer
 *
 * @param buf The buffer
 * @param fd The file descriptor
 * @param len Number of bytes to read from file
 */
int
buf_read_fd(buf_t *buf, int fd, size_t len)
{
	assert(buf);
	assert(buf->head);
	assert(buf->head->data);
	assert(2 < fd);
	assert(buf->pos >= buf->head->data && buf->pos < buf->head->end);

	chunk_t *ch = buf->tail;
	size_t avail = _AVAILABLE(ch);
	int retval;
	if (avail > len)
	{
		retval = _read_fd(fd, buf->pos, len);
		assert(0 < retval);

		buf->pos += len;
		DLEN_ADD(ch,len);
	}
	else
	{
		retval = _read_fd(fd, buf->pos, avail);
		assert(0 < retval);

		buf->pos += avail;
		DLEN_ADD(ch,avail);

		chunk_t *nch = new_chunk_with_size((len - avail) + 1);
		ch->next = buf->tail = nch;
		buf->pos = nch->data;

		size_t r = (len - avail);
		retval = _read_fd(fd, buf->pos, r);
		assert(0 < retval);

		DLEN_ADD(nch,r);
	}

	buf->dlen += len;
	return len;
}

static ssize_t
_write_fd(int fd, char *p, size_t len)
{
	assert(0 < fd);
	assert(p);
	assert(0 < len);

	ssize_t n;
	size_t r = len;
	while (r && (n = write(fd, p, r)))
	{
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
		}

		p += n;
		r -= n;
	}

	return len;
}

/**
 * Write the contents of the buffer to a file descriptor.
 *
 * @param buf The buffer
 * @param fd The file descriptor
 */
int
buf_write_fd(buf_t *buf, int fd)
{
	assert(buf);
	assert(0 < fd);

	DBG("Writing buffer contents to file descriptor %d\n", fd);

	chunk_t *ch = buf->head;
	ssize_t n;
	size_t towrite;
	char *pos = NULL;
	while (ch)
	{
		//DBG("Current chunk length: %lu\n", ch->dlen);
		towrite = ch->dlen;
		pos = ch->data;

		n = _write_fd(fd, pos, towrite);
		assert(n == towrite);
		//DBG("Wrote %lu bytes to file descriptor %d\n", towrite, fd);
		ch = ch->next;
	}

fail:
	return -1;
}

/**
 * Add data to the buffer. Length is required
 * so we can add binary data to the buffer.
 *
 * @param buf The buffer
 * @param data The data to add
 * @param len The length of the data
 */
int
buf_add(buf_t *buf, void *data, size_t len)
{
	assert(buf);
	assert(data);
	assert(0 < len);

	size_t r = _AVAILABLE(buf->head);
	chunk_t *ch = buf->tail;
	DBG("Space available in tail chunk: %lu bytes\n", r);

	if (r > len)
	{
		DBG("Copying %lu bytes into chunk\n", len);
		memcpy(buf->pos, data, len);
		buf->pos += len;
		DLEN_ADD(ch,len);
	}
	else
	{
		DBG("Copying %lu bytes into chunk\n", r);
		char *p = (char *)data;
		memcpy(buf->pos, data, r);
		DLEN_ADD(ch,r);

		DBG("Creating new chunk of size %lu bytes\n", len - r);
		chunk_t *nch = new_chunk_with_size(len - r);
		assert(nch);

		buf->tail->next = nch;
		buf->tail = nch;
		buf->pos = nch->data;

		DBG("Copying %lu bytes into new chunk\n", len - r);
		p += r;
		memcpy(buf->pos, p, (len - r));
		buf->pos += (len - r);
		DLEN_ADD(nch,(len-r));
	}

	buf->dlen += len;
	return (int)len;
}

/**
 * Return a heap-allocated string containing the
 * contents of a portion of the buffer without
 * removing said contents from the buffer. We
 * read from the front of the buffer.
 *
 * @param buf The buffer
 * @param len The number of bytes to copy
 */
char *
buf_peek(buf_t *buf, size_t len)
{
	BUF_ASSERT(buf);

	size_t dlen = _USED(buf->head);

	if (0 >= dlen)
	{
		DBG("buf_peek: head chunk has length <= 0\n");
		return NULL;
	}

	char *res = calloc(len+1, 1);
	assert(res);
	assert(0 < len);
	assert(len < UINT_MAX); // seems a reasonable limit

	chunk_t *ch = buf->head;
	char *p = res;
	char *pos = ch->data;
	size_t c;

	DBG("Total data in buffer: %lu\n", buf->dlen);
	DBG("Chunk used: %lu\n", _USED(ch));
	DBG("Chunk data: %s\n", ch->data);
	while (len)
	{
		c = _USED(ch);
		assert(0 < c);

		if (c > len)
			c = len;
		memcpy(p, pos, c);

		pos += c;
		p += c;
		len -= c;

		if (pos >= ch->end)
		{
			ch = ch->next;
			if (!ch)
				break;
			pos = ch->data;
		}
	}

	return res;
}


/**
 * Shift the data in the buffer from a position in a chunk
 * forward a number of bytes. If there isn't enough space
 * available at the end of the chunk for the shift, we put
 * the excess in a new chunk.
 *
 * @param buf The buffer
 * @param pos The position within one of the chunks from which we shift
 * @param by The number of bytes by which we shift
 */
int
buf_shift(buf_t *buf, char *pos, size_t shift)
{
	BUF_ASSERT(buf);
	if (0 == shift)
		return 0;
	assert(0 < shift && shift < INT_MAX/2);

	chunk_t *ch = _get_chunk_for_pos(buf, pos);

	CHUNK_ASSERT(ch);
	assert(IS_IN_CHUNK(pos,ch));

	ssize_t avail = _AVAILABLE(ch);
	ssize_t amt = _USED(ch) - (pos - ch->data);
	ssize_t c = shift - avail;

	assert(0 <= avail);
	assert(0 < amt);

	if (0 < c)
	{
		chunk_t *nch = new_chunk_with_size(c+256);
		CHUNK_ASSERT(nch);

		if (c >= amt)
		{
			ssize_t s = c - amt;
			DBG("c >= amt: c:%lu,amt:%lu,s:%ld\n", c, amt, s);
			//sleep(4);
			assert(0 <= s);
			assert((nch->data + s + amt) <= nch->end);
			memcpy(nch->data + s, pos, amt);
			if (s)
				memset(nch->data, 0, s);
			PRN(nch->data, amt+s);
			//sleep(4);
			PRN(pos, amt);
			memset(pos, 0, amt);
			PRN(pos, amt);
			//sleep(4);
			DLEN_ADD(nch,amt+s);
		}
		else
		{
			assert((pos + (amt - c)) <= DATA_END(ch));
			assert((nch->data + c) <= nch->end);
			memcpy(nch->data, pos + (amt - c), c);
			assert((pos + shift) <= ch->end);
			memmove(pos + shift, pos, amt - c);
			memset(pos, 0, shift);

			nch->dlen = c;
			DLEN_ADD(ch,avail);
		}

		nch->next = ch->next;
		ch->next = nch;
	}
	else
	{
		memmove(pos + shift, pos, amt);
		memset(pos, 0, shift);

		DLEN_ADD(ch,shift);
	}

	return 0;
}

/**
 * Collapse a buffer down to POS from POS + BY.
 *
 * @param buf The buffer
 * @param pos The position to which we collapse
 * @param by The amount by which we collapse
 */
int
buf_collapse(buf_t *buf, char *pos, size_t by)
{
	BUF_ASSERT(buf);
	assert(pos);
	assert(0 <= by);

	if (0 == by)
		return 0;

	chunk_t *ch = _get_chunk_for_pos(buf, pos);
	CHUNK_ASSERT(ch);

	size_t r = DATA_END(ch) - pos;
	size_t b = by;
	if (b > r)
	{
		DBG("b > r\n");
		chunk_t *next = ch->next;
		CHUNK_ASSERT(next);
		char *p = next->data;
		b -= r;
		while (1)
		{
			r = DATA_END(next) - p;
			if (r > b)
			{
				memset(p, 0, b);
				p += b;
				b = 0;
				size_t rm = DATA_END(next) - p;
				size_t sp = ch->end - pos;
				if (sp >= rm)
				{
					memcpy(pos, p, rm);
					DLEN_ADD(ch,(rm - (DATA_END(ch) - pos)));
				}
				else
				{
					memcpy(pos, p, sp);
					ch->dlen = ch->len;
					p += sp;
					size_t mv = (DATA_END(next) - p);
					memmove(next->data, p, mv);
					next->dlen = mv;
					memset(next->data + mv, 0, next->end - (next->data + mv));
				}

				break;
			}
			else
			{
				ch->next = next->next;
				free_chunk(next);
				next = ch->next;
				p = next->data;
				b -= r;
			}
		}
	}
	else
	{
		DBG("b <= r\n");
		char *p = pos + by;
		size_t amt = DATA_END(ch) - p;
		memmove(pos, p, amt);
		memset(pos + amt, 0, DATA_END(ch) - (pos + amt));
		DLEN_SUB(ch,by);
	}

	return 0;
}


#ifdef DEBUG
# define CHECK_LEN(b,p,l) \
do { \
	chunk_t *_ch = _get_chunk_for_pos((b),(p)); \
	CHUNK_ASSERT(_ch); \
	size_t __tlen = 0; \
	for (; _ch; _ch = _ch->next) \
		__tlen += _ch->dlen; \
	assert((l) <= __tlen); \
} while (0)
#else
# define CHECK_LEN(b,p,l)
#endif

int
buf_overwrite(buf_t *buf, char *pos, char *with, size_t len)
{
	BUF_ASSERT(buf);
	assert(pos);
	assert(with);

	CHECK_LEN(buf, pos, len);
	chunk_t *ch = _get_chunk_for_pos(buf, pos);
	CHUNK_ASSERT(ch);
	assert(IS_IN_CHUNK(pos,ch));

	ssize_t r = DATA_END(ch) - pos;
	assert(0 < r);

	if (r >= len)
	{
		DBG("r >= len\n");
		assert((pos + r) <= DATA_END(ch));
		memcpy(pos, with, len);
		PRN(pos,len);
		return 0;
	}
	else
	{
		DBG("r < len\n");
		char *w = with;
		while (len)
		{
			DBG("Copying %lu bytes of data from 'w' to 'pos'\n", r);

			assert((pos + r) <= DATA_END(ch));
			memcpy(pos, w, r);

			DBG("PRN(pos,%ld)\n", r);
			PRN(pos,r);
			//sleep(4);

			w += r;
			len -= r;
			if (0 == len)
				break;

			ch = ch->next;

			if (!ch)
			{
				DBG("No next chunk -- %lu bytes remaining of 'with' to write...\n", len);
				return -1;
			}

			CHUNK_ASSERT(ch);
			pos = ch->data;
			r = DATA_END(ch) - pos;
			assert(r == ch->dlen && 0 < r);

			if (r > len)
				r = len;
		}
	}

	return 0;
}

/**
 * Compare data in buffer at position P
 * with that specified in F. The pattern
 * may cross a border between two chunks
 * of memory. In that case, compare a byte
 * at a time and change chunks accordingly.
 */
static int
BMEMCMP(chunk_t *ch, char *pos, char *f, size_t len, match_t *m)
{
	memset(m, 0, sizeof(*m));
	assert(IS_IN_CHUNK(pos,ch));
	ssize_t r = DATA_END(ch) - pos;
	assert(0 <= r);

	if (r >= len)
	{
		assert(r >= len);
		if (!memcmp(pos, f, len))
		{
			m->s = pos;
			m->e = pos + len;
			m->straddles = 0;
			m->ch1 = ch;
			m->ch2 = NULL;

			return 0;
		}
		else
			return 1;
	}
	else
	{
		assert(r < len);
		char *e = DATA_END(ch);
		char *p = pos;
		char *_f = f;
		chunk_t *c = ch;
		assert(c == ch);
		while (c)
		{
			DBG("Comparing %c and %c\n", *p, *_f);
			if (*p != *_f)
				break;
			++p;
			++_f;
			if (p >= e)
			{
				c = c->next;
				p = c->data;
				e = DATA_END(c);
			}
		}

		if ((_f - f) == len)
		{
			assert(c != ch);
			assert(c == ch->next);
			m->s = pos;
			m->e = p;
			m->ch1 = ch;
			m->ch2 = ch->next;
			m->straddles = 1;

			DBG("\n\n\n\n\nPATTERN STRADDLES TWO CHUNKS\n\n\n\n\n");
			return 0;
		}
		else
			return 1;
	}
}

int
buf_replace(buf_t *buf, char *pos, size_t len, char *with)
{
	BUF_ASSERT(buf);
	chunk_t *ch = _get_chunk_for_pos(buf, pos);
	CHUNK_ASSERT(ch);

	size_t len2 = strlen(with);
	int longer = len2 > len;
	ssize_t r = DATA_END(ch) - pos;
	size_t diff;
	char *w = with;

	if (longer)
	{
		diff = len2 - len;
		if (r > len)
			buf_shift(buf, ch->next->data, diff);
		else
			buf_shift(buf, pos, diff);

		buf_overwrite(buf, pos, with, len2);
	}
	else
	{
		diff = len - len2;
		buf_collapse(buf, pos, diff);
		buf_overwrite(buf, pos, with, len2);
	}
}

int
buf_replace_all_instances(buf_t *buf, char *r, char *with)
{
	BUF_ASSERT(buf);
	chunk_t *ch = buf->head;
	CHUNK_ASSERT(ch);
/*
 * For example, stupidly wanting to replace all instances of "//"
 * with "file:///path/to/directory/" since we find the pattern
 * we want to replace in the replacement.
 */
	if (strstr(with, r))
	{
		fprintf(stderr, "Pattern we wish to replace is contained within replacement...\n");
		fprintf(stderr, "Replace: %s, with %s\n", r, with);
		assert(0);
	}
	assert(!strstr(with, r));

	size_t len1 = strlen(r);
	size_t len2 = strlen(with);
	int longer = len2 > len1;

	char *pos = ch->data;
	char *spos;
	char c = r[0];
	match_t m = {0};


	while (1)
	{
		spos = pos;
		pos = memchr(spos, c, DATA_END(ch) - spos);
		if (!pos)
		{
			if (!ch->next)
				break;

			//DBG("Going to next chunk\n");
			ch = ch->next;
			CHUNK_ASSERT(ch);
			pos = ch->data;
			//DBG("Starting at chunk data at address %p\n", pos);
			continue;
		}

		if (pos == spos)
		{
			++pos;
			continue;
		}

		if (BMEMCMP(ch, pos, r, len1, &m))
		{
			++pos;
			continue;
		}

		DBG("Matched data in buffer\n");
		assert(*pos == c);
		if (longer)
		{
			int diff = len2 - len1;

			if (m.straddles)
			{
			/*
			 * [ https:/ ] [ /............................ ]
			 * [ file:// ] [ /home/proboscis/Archived_Web/ ]
			 */
				size_t _l = DATA_END(ch) - pos;
				int i = 0;
				while (_l--)
				{
					DBG("%c and %c\n", *(pos+i), *(r+i));
					assert(*(pos+i) == *(r+i));
					++i;
				}

				assert(pos == m.s);
				assert((DATA_END(ch) - pos) < len1);
				DBG("Overwriting data that straddles two chunks\n");
				assert(IS_IN_CHUNK(m.s, ch));
				DBG("Shifting data in next chunk by %d bytes\n", diff);
				buf_shift(buf, m.ch2->data, diff);
				DBG("Finished shifting\nOverwriting data\n");
				buf_overwrite(buf, pos, with, len2);
				DBG("Finished overwriting\n");
			}
			else
			{
				buf_shift(buf, pos, diff);
				buf_overwrite(buf, pos, with, len2);
				DBG("Overwote data: \"%*.*s\"\n", (int)len2+4, (int)len2+4, pos);
				//strncpy(pos, with, len2);
			}
		}
		else
		{
			int diff = len1 - len2;
			buf_collapse(buf, pos, diff);
			buf_overwrite(buf, pos, with, len2);
			DBG("Overwote data: \"%*.*s\"\n", (int)len2+4, (int)len2+4, pos);
			//strncpy(pos, with, len2);
		}

		++pos;
	}
}

#ifdef DEBUG
void
dump_border_data(buf_t *buf)
{
	BUF_ASSERT(buf);
	chunk_t *prev = buf->head;
	chunk_t *ch = prev->next;

	CHUNK_ASSERT(prev);
	CHUNK_ASSERT(ch);

	int i = 0;
	while (ch)
	{
		fprintf(stderr, "\n\n---- CHUNK %d - %d ----\n\n", i, i+1);
		PRN(DATA_END(prev) - 8, 8);
		fprintf(stderr, "\n ---- END CHUNK %d ----\n", i);
		PRN(ch->data, 8);
		fprintf(stderr, "\n ---- END CHUNK %d ----\n", i+1);
		prev = ch;
		ch = ch->next;
		i += 2;
	}
}
#endif

/**
 * Copy data from all chunks into a single chunk
 */
void
buf_coalesce(buf_t *buf)
{
	BUF_ASSERT(buf);

	chunk_t *ch = buf->head;
	size_t len = 0;

	for (; ch; ch = ch->next)
		len += ch->dlen;

	DBG("Total data in all chunks: %lu bytes\n", len);

	chunk_t *prev;
	chunk_t *nch = new_chunk_with_size(len);
	char *p = nch->data;
	for (prev = buf->head, ch = prev->next; prev; )
	{
		memcpy(p, prev->data, prev->dlen);
		p += prev->dlen;
		DLEN_ADD(nch,prev->dlen);
		free_chunk(prev);
		prev = ch;
		if (ch)
			ch = ch->next;
	}

	assert(nch->dlen == len);
	buf->head = buf->tail = nch;
	return;
}
