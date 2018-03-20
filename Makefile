all:
	gcc -O3 -msha -mavx2  sha256/src/*.c sha256/bench/*.c prng/*.c cpuid/*.c    -Isha256/include -Lsha256/src -I. -lcrypto -o bench.x

clean:
	rm -f bench.x
	
	

