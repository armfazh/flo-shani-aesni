OPENSSL_INCLUDE_DIR=/opt/ossl102/include
OPENSSL_LIBRARY_DIR=/opt/ossl102/lib
LIB=./lib
BIN=./bin


.INTERMEDIATE:  prng/flo-random.o           \
                cpuid/flo-cpuid.o           \
                aegis/aegis_ref.o           \
                aegis/aegis_opt.o           \
                bench/bench_aegis.o         \
                aes/aesni.o                 \
                bench/bench_aes.o           \
                sha256/flo-shani.o          \
                sha256/sha256_vectorized.o  \
                bench/bench_sha256.o

all: folder libs apps
libs: lib/libflo-prng.a lib/libflo-cpuid.a
apps: bin/bench_aegis bin/bench_aes bin/bench_sha256

# Library PRNG
lib/libflo-prng.a: prng/flo-random.o
	$(AR) rcvs $@ $^
prng/flo-random.o: prng/flo-random.c prng/flo-random.h

# Library CPUID
lib/libflo-cpuid.a: cpuid/flo-cpuid.o
	$(AR) rcvs $@ $^
cpuid/flo-cpuid.o: cpuid/flo-cpuid.c cpuid/flo-cpuid.h
	$(CC) -c -o $@ $< -I$(OPENSSL_INCLUDE_DIR)
# Library AEGIS
lib/libflo-aegis.a: aegis/aegis_opt.o aegis/aegis_ref.o
	$(AR) rcvs $@ $^
aegis/aegis_ref.o: aegis/aegis_ref.c aegis/flo-aegis.h
	$(CC) -c -o $@ $< -I./aegis -maes
aegis/aegis_opt.o: aegis/aegis_opt.c aegis/flo-aegis.h
	$(CC) -c -o $@ $< -I./aegis -maes

# Library AES
lib/libflo-aes.a: aes/aesni.o
	$(AR) rcvs $@ $^
aes/aesni.o: aes/aesni.c aes/flo-aesni.h
	$(CC) -c -o $@ $< -I./aes -maes -msse4.1

# Library SHANI
lib/libflo-shani.a: sha256/flo-shani.o sha256/sha256_vectorized.o
	$(AR) rcvs $@ $^
sha256/flo-shani.o: sha256/flo-shani.c sha256/flo-shani.h
	$(CC) -c -o $@ $< -I./sha256 -msha -mssse3
sha256/sha256_vectorized.o: sha256/sha256_vectorized.c sha256/flo-shani.h
	$(CC) -c -o $@ $< -I./sha256 -mavx2

# App Bench AEGIS
bin/bench_aegis: bench/bench_aegis.o lib/libflo-aegis.a lib/libflo-cpuid.a lib/libflo-prng.a
	$(CC) $(CFLAGS) -o $@ $< -Llib -lflo-aegis -lflo-prng -lflo-cpuid -I$(OPENSSL_INCLUDE_DIR) -L$(OPENSSL_LIBRARY_DIR) -lcrypto
bench/bench_aegis.o: bench/bench_aegis.c bench/clocks.h
	$(CC) -c -o $@ $< -I./aegis -I./prng -I./cpuid

# App Bench AES
bin/bench_aes: bench/bench_aes.o lib/libflo-aes.a lib/libflo-cpuid.a lib/libflo-prng.a
	$(CC) $(CFLAGS) -o $@ $< -Llib -lflo-aes -lflo-prng -lflo-cpuid -I$(OPENSSL_INCLUDE_DIR) -L$(OPENSSL_LIBRARY_DIR) -lcrypto
bench/bench_aes.o: bench/bench_aes.c bench/clocks.h
	$(CC) -c -o $@ $< -I./aes -I./prng -I./cpuid

# App Bench SHA
bin/bench_sha256: bench/bench_sha256.o lib/libflo-shani.a lib/libflo-cpuid.a lib/libflo-prng.a
	$(CC) $(CFLAGS) -o $@ $< -Llib -lflo-shani -lflo-prng -lflo-cpuid -I$(OPENSSL_INCLUDE_DIR) -L$(OPENSSL_LIBRARY_DIR) -lcrypto
bench/bench_sha256.o: bench/bench_sha256.c bench/clocks.h
	$(CC) -c -o $@ $< -I./sha256 -I./prng -I./cpuid


folder:
	@if [ ! -x $(LIB) ];	then mkdir $(LIB); 	fi
	@if [ ! -x $(BIN) ];	then mkdir $(BIN); 	fi

clean:
	rm -f bin/* lib/*
