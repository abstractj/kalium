ctest.so: src/main/ext/ctest.c
	gcc -shared -o src/main/ext/bin/$@ $<

clean:
	-rm src/main/ext/bin/*.so

