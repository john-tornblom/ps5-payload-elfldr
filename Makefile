PS5_HOST ?= ps5
PS5_PORT ?= 9020

CC := clang
LD := ld.lld

CFLAGS  := -target x86_64-pc-none -fPIE -fno-stack-protector -ffreestanding \
           -fno-builtin -nostdlib -nostdinc -Wall
LDFLAGS := -pie -T elf_x86_64.x

OBJS := crt.o libc.o kern.o dynlib.o pt.o bootstrap.o elfldr.o

all: elfldr.elf

elfldr-socksrv_elf.c: elfldr-socksrv.elf
	xxd -i $^ > $@

elfldr-socksrv.elf: $(OBJS) main-socksrv.o
	$(LD) $(LDFLAGS) -o $@ $^

elfldr.elf: $(OBJS) main.o
	$(LD) $(LDFLAGS) -o $@ $^

main-socksrv.o: main.c
	$(CC) -c $(CFLAGS) -o $@ $<

main.o: main.c elfldr-socksrv_elf.c
	$(CC) -c $(CFLAGS) -DELFLDR_BOOTSTRAP -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o *.elf elfldr-socksrv_elf.c

test: elfldr.elf
	nc -q0 $(PS5_HOST) $(PS5_PORT) < $^

