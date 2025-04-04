GCC=g++
PLUGINS_DIR:=$(shell $(GCC) -print-file-name=plugin)
ARCH := $(shell uname -m)
INSTALL_PATH = $(HOME)

ifeq ($(ARCH),aarch64)
	# Check if instrumentation can cope with branch-protection=standard and no-omit-leaf-frame-pointer
	# fedora glibc in particular is compiled with this
	# no-omit-leaf-frame-pointer is not available on gcc x86_64 as of this comment
	CXXFLAGS+= -march=armv8-a+lse -mbranch-protection=standard -mno-omit-leaf-frame-pointer
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
	cp ./libSoftwareCountersGcc.so $(INSTALL_PATH)
