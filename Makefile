VPATH = tsocks
CC = gcc
SERVER_SOURCE = server.c
LOCAL_SOURCE = local.c
COMMON_SOURCES = $(wildcard *.c)
SERVER_OBJS = $(SERVER_SOURCE:.c=.o)
LOCAL_OBJS = $(LOCAL_SOURCE:.c=.o)
COMMON_OBJS = $(COMMON_SOURCES:.c=.o)
CFLAGS = -I. -Wall
LDFLAGS = -L/usr/local/lib
LDLIBS = -levent
SERVER = server
LOCAL = local

.PHONY: all clean $(SERVER) $(LOCAL)

all: $(SERVER) $(LOCAL)

$(SERVER): $(COMMON_OBJS) $(SERVER_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(LOCAL): $(COMMON_OBJS) $(LOCAL_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(COMMON_OBJS) $(SERVER_OBJS) $(LOCAL_OBJS) $(SERVER) $(LOCAL)
