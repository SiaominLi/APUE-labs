obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: test_crypto
	make -C ../dist/modulebuild M=$(PWD) modules

cryptomod: cryptomod.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	# mkdir -p ../rootfs/modules
	# cp cryptomod.ko ../rootfs/modules
	rm ../dist/rootfs.cpio.bz2
	cp cryptomod.ko ../dist/rootfs/modules