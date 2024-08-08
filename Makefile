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

deps:
	curl https://raw.githubusercontent.com/sheredom/json.h/master/json.h > src/json.h
	curl https://raw.githubusercontent.com/gpakosz/uuid4/master/src/uuid4.c > src/uuid4.c
	curl https://raw.githubusercontent.com/gpakosz/uuid4/master/src/uuid4.h > src/uuid4.h
	sed -i 's/<uuid4.h>/"uuid4.h"/' src/uuid4.c
