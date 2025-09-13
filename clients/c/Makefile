CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -Wall -Wextra -Iinclude
LIBNAME = libtaric_client.a
OBJS = src/taric_client.o

all: $(LIBNAME)

$(LIBNAME): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test:
	@echo "No C tests yet"

clean:
	rm -f $(OBJS) $(LIBNAME)
