libctest.so: src/main/ext/ctest.c
	gcc -shared -o src/main/ext/bin/libctest.dylib $<

clean:
	-rm src/main/ext/bin/*.dylib

