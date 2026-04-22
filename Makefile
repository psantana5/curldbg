CC := gcc
CFLAGS := -O2 -Wall -Wextra -pthread -Iinclude
LDLIBS := -pthread -lssl -lcrypto
TARGET := curldbg
SRCS := src/main.c src/curldbg.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJS)
