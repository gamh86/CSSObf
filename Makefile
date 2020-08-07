CC = gcc

SOURCE_FILES := \
	buffer.c \
	cssobf.c \
	hash_bucket.c \
	main.c

DEBUG := 0

OBJ_FILES := ${SOURCE_FILES:.c=.o}
BINARY := cssobf

$(BINARY): $(OBJ_FILES)
ifeq ($(DEBUG),1)
	$(CC) -DDEBUG -g -o $(BINARY) $^
else
	$(CC) -o $(BINARY) $^
endif

$(OBJ_FILES): $(SOURCE_FILES)
ifeq ($(DEBUG),1)
	$(CC) -DDEBUG -g -c $(SOURCE_FILES)
else
	$(CC) -c $(SOURCE_FILES)
endif
