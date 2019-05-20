all: xmssdraft06sha256v17_1x xmssdraft06sha256v17_4x  xmssdraft06sha256v17_8x 
xmssdraft06sha256v17_1x:
	gcc -o xmssdraft07sha256v17_1x.x mainXMSS.c -lm -mavx2 -DXMSS_SHA2_1x -std=gnu99 -O3 -g0 -march=native -mtune=native -m64 -fno-aggressive-loop-optimizations -g
xmssdraft06sha256v17_4x:
	gcc -o xmssdraft07sha256v17_4x.x mainXMSS.c -lm -mavx2 -DXMSS_SHA2_4x -std=gnu99 -O3 -g0 -march=native -mtune=native -m64 -fno-aggressive-loop-optimizations -g
xmssdraft06sha256v17_8x:
	gcc -o xmssdraft07sha256v17_8x.x mainXMSS.c -lm -mavx2 -DXMSS_SHA2_8x -std=gnu99 -O3 -g0 -march=native -mtune=native -m64 -fno-aggressive-loop-optimizations -g

clean:
	rm *.x 
