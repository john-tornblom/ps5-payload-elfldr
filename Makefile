PS5_HOST    ?= ps5
PS5_PORT    ?= 9020
ELFLDR_PORT ?= 9021

CC  := clang
LD  := ld.lld
XXD := xxd

CFLAGS  := -target x86_64-pc-none -fPIE -fno-stack-protector -ffreestanding \
           -fno-builtin -nostdlib -nostdinc -Wall -Werror
LDFLAGS := -pie -T elf_x86_64.x

OBJS := crt.o libc.o kern.o dynlib.o pt.o elfldr.o

all: elfldr.elf hello_world.elf

elfldr.elf: $(OBJS) main.o
	$(LD) $(LDFLAGS) -o $@ $^

elfldr-socksrv.elf: $(OBJS) main-socksrv.o
	$(LD) $(LDFLAGS) -o $@ $^

payload_launchpad.elf: payload_launchpad.o
	$(LD) $(LDFLAGS) -o $@ $^

hello_world.elf: hello_world.o
	$(LD) $(LDFLAGS) -o $@ $^


main.o: main.c elfldr-socksrv_elf.c
	$(CC) -c $(CFLAGS) -DELFLDR_BOOTSTRAP -o $@ $<

elfldr-socksrv_elf.c: elfldr-socksrv.elf
	$(XXD) -i $^ > $@

elfldr.o: elfldr.c payload_launchpad_elf.c
	$(CC) -c $(CFLAGS) -o $@ $<

payload_launchpad_elf.c: payload_launchpad.elf
	$(XXD) -i $^ > $@

main-socksrv.o: main.c
	$(CC) -c $(CFLAGS) -DELFLDR_PORT=$(ELFLDR_PORT) -o $@ $<


%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o *.elf elfldr-socksrv_elf.c payload_launchpad_elf.c

test: elfldr.elf hello_world.elf
	nc -q0 $(PS5_HOST) $(PS5_PORT) < elfldr.elf
	@sleep 1
	nc -q0 $(PS5_HOST) $(ELFLDR_PORT) < hello_world.elf
