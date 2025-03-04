GCC=g++
PLUGINS_DIR:=$(shell $(GCC) -print-file-name=plugin)
ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
    $(error aarch64 not supported in this version of the gcc plugin)
endif

ifeq ($(ARCH),x86_64)
	OBJDUMP_FLAGS=-M intel
endif

PLUGIN_CXXFLAGS+= $(CXXFLAGS) -std=c++20 -fPIC -fno-rtti -O2 -I$(PLUGINS_DIR)/include -I../../src/preload

libSoftwareCountersGcc.so: plugin.cpp locations.h ../../src/preload/preload_interface.h
	$(GCC) -g -Wunused -shared $(PLUGIN_CXXFLAGS) plugin.cpp -o $@

run-plugin: libSoftwareCountersGcc.so
	@echo Instrumenting -O0 hello
	@echo =======================
	$(GCC) -O0 -fplugin=./libSoftwareCountersGcc.so $(CXXFLAGS) -g -o hello.noopt hello.c
	@echo Instrumenting -O2 hello
	@echo =======================
	$(GCC) -O2 -fdump-tree-all-raw -fplugin=./libSoftwareCountersGcc.so $(CXXFLAGS) -g -o hello hello.c
	@echo objdump -d -O2 hello
	@echo =======================
	objdump $(OBJDUMP_FLAGS) -dS ./hello
	@echo Running -O0 hello
	@echo =======================
	./hello.noopt
	@echo Running -O2 hello
	@echo =======================
	./hello

clean:
	rm -f hello hello.noopt hello.c.* libSoftwareCountersGcc.so

install: libSoftwareCountersGcc.so
	sudo cp ./libSoftwareCountersGcc.so /usr/lib/

hinstall: libSoftwareCountersGcc.so
	cp ./libSoftwareCountersGcc.so ~/
