all: libazk_premain.a libazk_premain.so


libazk_premain.a: azkaban_premain.o azk_premain.o
	ar cr libazk_premain.a azkaban_premain.o azk_premain.o

libazk_premain.so: azkaban_premain.c azk_premain.S dune.h
	gcc -shared -fPIC -o libazk_premain.so azkaban_premain.c azk_premain.S

clean:
	rm -rf *.so *.a *.o
