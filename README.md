# _Software Counters mode_ `rr`

_Software Counters mode_ `rr`, is a modified version of the
[rr](https://github.com/rr-debugger/rr.git) debugger that
allows users to do record/replay style debugging _without_
needing access to CPU Hardware Performance counters.
[Upstream](https://github.com/rr-debugger/rr.git) `rr` requires access
to CPU HW performance counters to function.

This is a new feature provided to `rr`. **You can now run rr in your Linux VMs
running on apple silicon macOS for example !**

Access to CPU Hardware Performance counters is usually not permitted in cloud VMs and containers
due to security reasons. Even if CPU HW Performance counters are available, sometimes they may be 
unreliable, non-deterministic, broken or high latency. Removing this requirement allows `rr` 
to be used in many more scenarios.

Running `rr` record/replay *without* access to CPU HW performance counters
is accomplished using **lightweight dynamic instrumentation**.

_Instead of traditionally invoking:_
```bash
$ rr record <your-program>
# ‼️ Invariably debug issues on why rr is complaining about not having access
#    to hardware counters
# ‼️ On Zen CPUs need to disable hardware SpecLockMap optimization which
#    requires root access on bare metal
# ‼️ Possibly suffer from non-fully deterministic and/or high latency counters
# ‼️ Abandon rr if you are in a cloud VM or container. Most cloud providers
#    or containers don't give access to CPU Hardware Performance counters
 
# 🤞 Fingers crossed that the CPU HW counters work well during replay
$ rr replay
```

_With "Software counters mode" rr, you simply invoke:_
```bash
# -W means Software Counters mode
$ rr record -W <your-program>
# Don't worry about CPU HW performance counters at all 😄 ! Profit !

# ⚠️ Must specify -W during replay also
$ rr replay -W 
# 😄 Profit !
```

> [!important]
> See https://github.com/sidkshatriya/rr.soft/wiki for detailed installation information and other FAQ.

> [!important]
> The _Software Counters mode_ `rr` executable is capable of running both _with_ and _without_ access to HW performance counters.
> In other words, the functionality of running _with_ HW performance counters is still available should you need it.
> Simply omit the `-W` flag when invoking `rr` !

## Details

This i.e. the https://github.com/sidkshatriya/rr.soft
repository modifies the plain vanilla [record/replay
(rr)](https://github.com/rr-debugger/rr.git) debugger to perform
record-replay _without_ needing access to CPU Hardware Performance Counters.

As a reminder:
> rr is a lightweight tool for recording, replaying and debugging execution of applications (trees of processes and threads).
Debugging extends gdb with very efficient reverse-execution, which in combination with standard gdb/x86 features like hardware data watchpoints, makes debugging much more fun.

The currently upstream version of `rr` *cannot* run _without_ Hardware
(HW) performance counters. Now, HW performance counters allow program
"progress" to be measured exactly and this is critical for deterministic
record/replay. Access to these counters is usually disabled in VMs and
containers for security reasons especially when running in the cloud. They
may also be broken, unreliable or high latency for some CPUs too.

Running `rr` record/replay *without* access to CPU HW performance counters
is accomplished using **lightweight dynamic instrumentation**.

### Isn't dynamic instrumentation slow and/or fragile ?

Yes, dynamic instrumentation of code to provide deterministic "ticks"
slows things down and can sometimes be fragile. In those scenarios
`clang` and `gcc` compiler plugins have been provided to _statically
instrument your program to provide the same deterministic ticks_ required
by Software Counters mode `rr`. Think of these compiler plugins as
akin to using statically instrumented ASAN e.g. `-fsanitize=address`
when compiling your code with `gcc` or `clang`.

Using these plugins to compile your programs is optional when doing
record/replay; it just speeds things up and provides some additional
robustness. Dynamic instrumentation is always used as a fallback if the
code has _not_ been statically instrumented. Dynamic instrumentation
will always be used when recording/replaying the executables/libraries
of non-gcc/clang compilers like Haskell/OCaml etc. for instance.

_This modification (using a combination of dynamic/static instrumentation
to provide "ticks") is termed "Software Counters" mode `rr`_.

Read more
[here](https://github.com/sidkshatriya/rr.soft/wiki#isnt-dynamic-instrumentation-slow-andor-fragile-)
for details on how to invoke the plugins.

## Platform & Linux distribution support

aarch64 and x86-64 is supported for software counters record/replay.

32-bit x86 is not planned to be supported, even in the future.

Currently the following distributions have been tested:
- Fedora 40, 41, 42
- Ubuntu 24.10, 25.04
- Debian Unstable

rr.soft should be able to work properly on other distributions too.

_If you are using aarch64, please use distributions with Linux kernel version >= 6.12
for best results._

### Running Software Counters mode `rr` within a container

Note that it is _not_ neccessary to run _Software Counters mode_ `rr` 
in the above distributions in a Virtual Machine or on bare metal. 

You can actually run _Software Counters mode_ `rr` in a container
using something like [podman](https://github.com/containers/podman) or 
[distrobox](https://github.com/89luca89/distrobox) !

```bash
$ distrobox enter fedora41
$ distrobox create --image fedora:42 --name fedora42
# Build Software Counters mode rr
# Run it !
```

## Why is Software counters mode not upstreamed to [`rr`](https://github.com/rr-debugger/rr.git) ?

Software Counters mode rr modifications _may_ be upstreamed in the future.

The ability to run without CPU HW performance counters is a large
feature patch and would require additional time and effort to get merged
upstream. It also depends on whether `rr` maintainers want dynamic/static
instrumentation in their codebase or wish to continue keeping `rr`
purely HW performance counters based.

The current objective is to get people to get playing with this feature
and see how it goes from there !

## Building, Installing and other FAQ

Building _Software Counters mode_ `rr` differs from upstream rr a
bit. Additionally the compiler plugins that are packaged in this
repository need to be built too.

There are some other requirements and things to keep in mind too.

> [!important]
> To get started and also read the FAQ goto https://github.com/sidkshatriya/rr.soft/wiki

## Code Contributions

Code contributions are welcome. However, if your code contribution
relates to plain vanilla `rr` please submit the contribution
[upstream](https://github.com/rr-debugger/rr.git).

This repository will occationally merge in all applicable commits in
upstream `rr`.

> [!important]
> Ordinarily, only code contributions related to Software Counters functionality are accepted in this repository.

## License

This repository is licensed under the same terms as https://github.com/rr-debugger/rr.git but the compiler plugins
packaged with this repository under the `compiler-plugins/` directory are under different licenses:

- The `clang` compiler plugin in the `compiler-plugins/SoftwareCountersClangPlugin` directory is licensed under `Apache License 2.0`
- The `gcc` compiler plugin in the `compiler-plugins/SoftwareCountersGccPlugin` directory is licensed under `GNU General Public License v3.0 or later`

---

# Overview

[![Build and test status](https://github.com/rr-debugger/rr/actions/workflows/build-and-test-main.yml/badge.svg?branch=master)](https://github.com/rr-debugger/rr/actions)

rr is a lightweight tool for recording, replaying and debugging execution of applications (trees of processes and threads).
Debugging extends gdb with very efficient reverse-execution, which in combination with standard gdb/x86 features like hardware data watchpoints, makes debugging much more fun. More information about the project, including instructions on how to install, run, and build rr, is at [https://rr-project.org](https://rr-project.org). The best technical overview is currently the paper [Engineering Record And Replay For Deployability: Extended Technical Report](https://arxiv.org/pdf/1705.05937.pdf).

Or go directly to the [installation and building instructions](https://github.com/rr-debugger/rr/wiki/Building-And-Installing).

Please contribute!  Make sure to review the [pull request checklist](/CONTRIBUTING.md) before submitting a pull request.

If you find rr useful, please [add a testimonial](https://github.com/rr-debugger/rr/wiki/Testimonials).

rr development is sponsored by [Pernosco](https://pernos.co) and was originated by [Mozilla](https://www.mozilla.org).

# System requirements

* Linux kernel >= 4.7 (for support of `__WALL` in `waitid()`)
  * rr 5.6.0 worked with kernel 3.11 (requiring `PTRACE_SETSIGMASK`)
* rr currently requires either:
  * An Intel CPU with [Nehalem](https://en.wikipedia.org/wiki/Nehalem_%28microarchitecture%29) (2010) or later microarchitecture.
  * Certain AMD Zen or later processors (see https://github.com/rr-debugger/rr/wiki/Zen)
  * Certain AArch64 microarchitectures (e.g. ARM Neoverse N1 or the Apple Silicon M-series)
* Running in a VM guest is supported, as long as the VM supports virtualization of hardware performance counters. (VMware and KVM are known to work; Xen does not.)
