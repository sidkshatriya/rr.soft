all: cmake

#--------------------------------
cmake:
	cmake -B build -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
	ninja -C build

test: cmake
	ninja -C build testSimpleCounter_test_soft_rr
	ninja -C build testCounter_test_soft_rr

opt: testCounterOpt.ll
	cat build/$<

dis: cmake
	ninja -C build testCounter
	objdump -M intel -d build/testCounter

compile_commands: cmake
	ninja -C build -t compdb > compile_commands.json

check: test

install: cmake
	sudo cp build/libSoftwareCounters.so /usr/lib/

hinstall: cmake
	cp build/libSoftwareCounters.so ~/

#--------------------------------
%Opt.ll: %.ll cmake
	ninja -C build $@

%.ll: %.c cmake
	ninja -C build $@

#--------------------------------
clean:
	rm -rf ./build

%.c:
