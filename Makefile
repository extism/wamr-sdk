.PHONY: build
build: extism-wamr
	mkdir -p build && cd build && cmake .. && $(MAKE)
	cp build/libextism-wamr.a .
	cp build/extism-wamr .

.PHONY: build
debug: extism-wamr
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && $(MAKE)
	cp build/libextism-wamr.a .
	cp build/extism-wamr .

test: build
	cd build && make test

clean:
	rm -rf ./build

extism-wamr:
	git submodule update --init
