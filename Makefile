build: extism-wamr
	mkdir -p build && cd build && cmake .. && $(MAKE)
	cp build/libextism-wamr.a .
	cp build/extism-wamr .

clean:
	rm -rf ./build

extism-wamr:
	git submodule update --init
