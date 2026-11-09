CC := gcc
CFLAGS := -Wall -Wextra

SRCS := $(wildcard *.c)
TARGETS := $(SRCS:.c=)

.PHONY: all run clean

all: $(TARGETS) run

run: $(TARGETS)
	sed -i 's/\r$$//' isolatedEnv.sh
	chmod +x isolatedEnv.sh
	./isolatedEnv.sh

capabilities: capabilities.c
	$(CC) $(CFLAGS) "$<" -o "$@" -lcap

seccomps: seccomps.c
	$(CC) $(CFLAGS) "$<" -o "$@" -lseccomp

%: %.c
	$(CC) $(CFLAGS) "$<" -o "$@"

clean:
	rm -f $(TARGETS)
