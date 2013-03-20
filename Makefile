libctest.so: ext/ctest.c
	gcc -shared -o ext/$@ $<

clean:
	-rm ext/*.so

