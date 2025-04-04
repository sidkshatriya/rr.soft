# Readme

GCC plugin to statically instrument C/C++ code with "ticks" so that
record/replay using _Software Counters mode_ `rr` can be done without
requiring access to HW performance counter events from the CPU PMU
(Performance Management Unit).

**Usage of this plugin when compiling your programs with `gcc`/`g++`
is optional**. It merely speeds up (and makes more robust) record/replay
in _Software Counters mode_ `rr`. If your program is not compiled with
this plugin _Software Counters mode_ `rr` falls back to using dynamic
instrumentation.

**The plugin can be compiled with gcc 13 and gcc 14 currently**.

The plugin depends on `gcc` internals. If you compile the plugin with
`gcc` 13 then use the plugin with `gcc` 13 only. If you compile the
plugin with gcc 14 then use the plugin with `gcc` 14 only (and so forth).

See https://github.com/sidkshatriya/rr.soft/wiki for further details on
how to build and use this plugin

**This release supports Linux x86-64 and Linux aarch64**.

## Usage

_After building the plugin (`libSoftwareCountersGcc.so`):_

```bash
# Static instrumentation using the libSoftwareCountersGcc.so plugin
# Assume the plugin is stored in $HOME for the purposes of this example
$ gcc -fplugin=$HOME/libSoftwareCountersGcc.so -o hello.c hello.c

# Works with C++ also
# Assume the plugin is stored in ~/ for the purposes of this example
$ g++ -fplugin=$HOME/libSoftwareCountersGcc.so -o hello hello.cpp

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

GNU General Public License v3.0 or later
