# Readme

Clang/LLVM plugin to statically instrument C/C++ code with "ticks"
so that record/replay using _Software Counters mode_ `rr` can be done
without requiring access to HW performance counter events from the CPU
PMU (Performance Management Unit).

**Usage of this plugin when compiling your programs with `clang`/`clang++`
is optional**. It merely speeds up (and makes more robust) record/replay
in _Software Counters mode_ `rr`. If your program is not compiled with
this plugin _Software Counters mode_ `rr` falls back to using dynamic
instrumentation.

**The plugin can be compiled with `clang` 18, 19, 20 currently**.

The plugin depends on `LLVM` internals. If you compile the plugin
with `clang` 18 then use the plugin with `clang` 18 only. If you compile
the plugin with `clang` 19 then use the plugin with `clang` 19 only
(and so forth).

See https://github.com/sidkshatriya/rr.soft/wiki for further details on
how to build and use this plugin.

**This release supports Linux x86-64 and Linux aarch64**.

## Usage

_After building the plugin (`libSoftwareCounters.so`):_

```bash
# Static instrumentation using the libSoftwareCounters.so plugin
# Assume the plugin is stored in $HOME for the purposes of this example
$ clang -fpass-plugin=$HOME/libSoftwareCounters.so -g -O2 -o hello.c hello.c

# Works with C++ also
# Assume the plugin is stored in ~/ for the purposes of this example
$ clang++ -fpass-plugin=$HOME/libSoftwareCounters.so -g -O2 -o hello hello.cpp

# Executable will work normally, might be a bit slower
$ ./hello

# Software Counters mode rr is a bit faster and more robust with statically
# instrumented executables/shared libraries
#
# Note the use -W flag to use software counters mode
$ rr record -W ./hello
$ rr replay -W
```

# Plugin License

Apache License 2.0
