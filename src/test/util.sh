#
# This file is included by foo.run test-driver files.  It provides
# some helpers for common test operations.  A driver file foo.run
# will want to include this file as follows
#
#  source `dirname $0`/util.sh
#
# It is essential that util.sh inherit its $n parameters from the
# driver script's parameters.
#
# Most tests are either "compare_test"s, which check that record and
# replay successfully complete and the output is the same, or,
# "debug_test"s, which launch a debugger script.  So the remainder of
# your test runner probably looks like
#
#  compare_test  # or, |debug_test|
#
# Test runners may set the environment variable $RECORD_ARGS to pass
# arguments to rr for recording.  This is only useful for tweaking the
# scheduler, don't use it for anything else.
#

if ! which pidof &> /dev/null; then
    pidof() {
        ps ax -o 'pid= exe=' | grep ' \(\|.*/\)'"$1"'$' | awk '{print $1}'
    }
fi

#  delay_kill <sig> <delay_secs> <proc>
#
# Deliver the signal |sig|, after waiting |delay_secs| seconds, to the
# process named |proc|.  If there's more than |proc|, the signal is
# not delivered.
function delay_kill { sig=$1; delay_secs=$2; proc=$3
    sleep $delay_secs

    pid=""
    for i in `seq 1 5`; do
        live=`ps ax -o 'pid= cmd=' | awk '{print $1 " " $2}' | grep $proc`
        num=`echo "$live" | wc -l`
        if [[ "$num" -eq 1 ]]; then
            pid=`echo "$live" | awk '{print $1}'`
            break
        fi
        sleep 0.1
    done

    if [[ "$num" -gt 1 ]]; then
        test_passed=n
        echo FAILED: "$num" of "'$proc'" >&2
        exit 1
    elif [[ -z "$pid" ]]; then
        test_passed=n
        echo FAILED: process "'$proc'" not located >&2
        exit 1
    fi

    # Wait for the test to print "ready", indicating it has completed
    # any required setup.
    until grep -q ready record.out; do
        sleep 0
    done

    kill -s $sig $pid
    if [[ $? != 0 ]]; then
        # Sometimes we fail to deliver a signal to a process because
        # it finished first (due to scheduling races). That's a benign
        # failure.
        echo signal $sig not delivered to "'$proc'", letting test succeed anyway
    else
        echo Successfully delivered signal $sig to "'$proc'"
    fi
}

function fatal { #...
    echo "$@" >&2
    exit 1
}

function onexit {
    cd
    if [[ "$test_passed" == "y" ]]; then
        if [[ "$tmp_workdir" != "" ]]; then
            rm -rf $tmp_workdir
        fi
        if [[ "$nontmp_workdir" != "" ]]; then
            rm -rf $nontmp_workdir
        fi
    else
        echo -n Test $TESTNAME failed, leaving behind $tmp_workdir
        (rmdir "$nontmp_workdir" 2>/dev/null && echo) || echo " and $nontmp_workdir"
        echo To replay the failed test, run
        echo " " _RR_TRACE_DIR="$workdir" rr replay
        exit 1
    fi
}

function parent_pid_of { pid=$1
    ps -p $pid -o ppid=
}

function usage {
    echo Usage: "util.sh TESTNAME [LIB_ARG] [OBJDIR]"
}

if [[ ! -z "$SOFTWARE_COUNTING_STRATEGY" ]]; then
    SOFTWARE_COUNTING_STRATEGY="--scs=$SOFTWARE_COUNTING_STRATEGY"
fi

MAYBE_SOFTWARE_COUNTERS=""
if [[ -z "$TEST_HARDWARE_PMU" ]]; then
    MAYBE_SOFTWARE_COUNTERS="--software-counters"
fi
GLOBAL_OPTIONS="$MAYBE_SOFTWARE_COUNTERS --suppress-environment-warnings --fatal-errors"

UNBOUND_OPTION=""
if [[ ! -z "$TEST_WITH_UNBOUND_CPU" ]]; then
    UNBOUND_OPTION="-u"
fi

# Note enabling software counters in GLOBAL_OPTIONS !
if [[ "$NO_CHECK_CACHED_MMAP" == "" ]]; then
    GLOBAL_OPTIONS="${GLOBAL_OPTIONS} --check-cached-mmaps"
fi

SRCDIR=`dirname ${BASH_SOURCE[0]}`/../..
SRCDIR=`realpath $SRCDIR`

TESTNAME=$1
if [[ "$TESTNAME" == "" ]]; then
    [[ $0 =~ ([A-Za-z0-9_]+)\.run$ ]] || fatal "FAILED: bad test script name"
    TESTNAME=${BASH_REMATCH[1]}
fi
if [[ $TESTNAME =~ ([A-Za-z0-9_]+)_32$ ]]; then
    bitness=_32
    TESTNAME_NO_BITNESS=${BASH_REMATCH[1]}
else
    TESTNAME_NO_BITNESS=$TESTNAME
fi

# We may want to retrieve this from python
export TESTNAME=$TESTNAME

LIB_ARG=$2
OBJDIR=$3
if [[ "$OBJDIR" == "" ]]; then
    # Default to assuming that the user's working directory is the
    # src/test/ directory within the rr clone.
    OBJDIR="$SRCDIR/../obj"
fi
if [[ ! -d "$OBJDIR" ]]; then
    fatal "FAILED: objdir missing"
fi
OBJDIR=`realpath $OBJDIR`
TIMEOUT=$4
if [[ "$TIMEOUT" == "" ]]; then
    TIMEOUT=120
fi

# The temporary directory we create for this test run.
workdir=
# A temporary directory likely to be in a tmpfs. Usually same as 'workdir'.
tmp_workdir=
# Another temporary directory that we created for this test run, in a real
# (non-tmpfs) filesystem if possible. It might be empty or still in a tmpfs.
nontmp_workdir=
# Did the test pass?  If not, then we'll leave the recording and
# output around for developers to debug, and exit with a nonzero
# exit code.
test_passed=y
# The unique ID allocated to this test directory.
nonce=

# Set up the environment and working directory.
export TESTDIR="${SRCDIR}/src/test"

# Make rr treat temp files as durable. This saves copying all test
# binaries into the trace.
export RR_TRUST_TEMP_FILES=1

# Have rr processes coordinate to not oversubscribe CPUs
export _RR_CPU_LOCK_FILE="/tmp/rr-test-cpu-lock"

# Set options to find rr and resource files in the expected places.
export PATH="${OBJDIR}/bin:${PATH}"

if [[ -z "$_RR_PATCH_LOC_DB_DIR" ]]; then
    export _RR_PATCH_LOC_DB_DIR="${OBJDIR}/patch-loc-cache"
fi

# Resource path is normally the same as the build directory, however, it is
# slightly different when using the installable testsuite. The installable
# testsuite will look for resources under DESTDIR/CMAKE_INSTALL_PREFIX. We
# can detect if it's the installable testsuite being run by checking if the
# rr binary exists in the build directory.
if [[ -f "$OBJDIR/bin/rr" ]]; then
    RESOURCE_PATH=$OBJDIR
else
    # The resources are located at DESTDIR/CMAKE_INSTALL_PREFIX. We don't have
    # access to these variables while running the testsuite. However, OBJDIR is
    # set as DESTDIR/CMAKE_INSTALL_PREFIX/CMAKE_INSTALL_LIBDIR/rr/testsuite/obj.
    # We can use this to locate the resources by going up exactly 4 directories.
    RESOURCE_PATH=`realpath $OBJDIR/../../../..`
fi

GLOBAL_OPTIONS="${GLOBAL_OPTIONS} --resource-path=${RESOURCE_PATH}"

which rr >/dev/null 2>&1
if [[ "$?" != "0" ]]; then
    fatal FAILED: rr not found in PATH "($PATH)"
fi

if [[ ! -d $SRCDIR ]]; then
    fatal FAILED: SRCDIR "($SRCDIR)" not found. objdir and srcdir must share the same parent.
fi

if [[ ! -d $TESTDIR ]]; then
    fatal FAILED: TESTDIR "($TESTDIR)" not found.
fi

RR_EXE=rr

# Our test programs intentionally crash a lot. Don't generate coredumps for them.
ulimit -c 0

# NB: must set up the trap handler *before* mktemp
trap onexit EXIT
workdir=`mktemp -dt rr-test-$TESTNAME-XXXXXXXXX`
tmp_workdir=$workdir
nontmp_workdir=`mktemp -p $PWD -dt rr-test-$TESTNAME-XXXXXXXXX`
cd $workdir
# NB: the testsuite should run on any system with different settings,
#     so create a reasonable default for all tests
export LC_ALL=C

# XXX technically the trailing -XXXXXXXXXX isn't unique, since there
# could be "foo-123456789" and "bar-123456789", but if that happens,
# buy me a lottery ticket.
baseworkdir=$(basename ${workdir})
nonce=${baseworkdir#rr-test-$TESTNAME-}

##--------------------------------------------------
## Now we come to the helpers available to test runners.  This is the
## testing "API".
##

function fails { why=$1;
    echo NOTE: Skipping "'$TESTNAME'" because it fails: $why
    exit 0
}

# If the test takes too long to run without the syscallbuf enabled,
# use this to prevent it from running when that's the case.
function skip_if_no_syscall_buf {
    if [[ "-n" == "$LIB_ARG" ]]; then
        echo NOTE: Skipping "'$TESTNAME'" because syscallbuf is disabled
        exit 0
    fi
}

# If the systemd version doesn't allow disabling RDRAND, skip the test,
# because it might trigger systemd code.
function skip_if_old_systemd {
    systemd_version=`systemctl --version | head -n1 | cut -d' ' -f2`
    if [[ $systemd_version != "" && $systemd_version < 247 ]]; then
        echo "can't disable RDRAND for systemd, skipping test"
        exit 0
    fi
}

function skip_if_test_32_bit {
    if [[ "_32" == $bitness ]]; then
        echo NOTE: Skipping "'$TESTNAME'" because 32-bit test
        exit 0
    fi
}

function skip_if_rr_32_bit {
    if [[ "$(file $RESOURCE_PATH/lib/rr/librrpage.so | grep 32-bit -c)" == "1" ]]; then
        echo NOTE: Skipping "'$TESTNAME'" because 32-bit rr
        exit 0
    fi
}

function skip_if_rr_32_bit_with_shell_64_bit {
    if [[ "$(file $RESOURCE_PATH/lib/rr/librrpage.so | grep 32-bit -c)" == "1" ]] &&
       [[ "$(file -L $(which sh) | grep 64-bit -c)" == "1" ]];
    then
        echo NOTE: Skipping "'$TESTNAME'" because 32-bit rr with 64-bit shell
        exit 0
    fi
}

# If the test is causing an unrealistic failure when the syscallbuf is
# enabled, skip it.  This better be a temporary situation!
function skip_if_syscall_buf {
    if [[ "" == "$LIB_ARG" ]]; then
        echo NOTE: Skipping "'$TESTNAME'" because syscallbuf is enabled
        exit 0
    fi
}

function just_record { exe="$1"; exeargs=$2;
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT record.err \
        $RR_EXE $GLOBAL_OPTIONS record --bind-to-cpu=any $SOFTWARE_COUNTING_STRATEGY $LIB_ARG $RECORD_ARGS "$exe" $exeargs 1> record.out 2> record.err
}

function save_exe { exe=$1;
    # If the installable testsuite is being run, most of the exes will
    # be located under OBJDIR and the remaining under RESOURCE_PATH.
    if [[ -f "${OBJDIR}/bin/$exe" ]]; then
        EXE_PATH=$OBJDIR/bin/$exe
    else
        EXE_PATH=$RESOURCE_PATH/bin/$exe
    fi
    cp "${EXE_PATH}" "$exe-$nonce"
}

function switch_to_nontmp_workdir_if_possible {
    if [[ "$nontmp_workdir" != "" ]]; then
        workdir=$nontmp_workdir
        cd $workdir
    fi
}

# Record $exe with $exeargs.
function record { exe=$1;
    save_exe "$exe"
    just_record "./$exe-$nonce" "$2 $3 $4 $5"
}

#  record_async_signal <signal> <delay-secs> <test>
#
# Record $test, delivering $signal to it after $delay-secs.
# If for some reason delay_kill doesn't run in time, the signal
# will not be delivered but the test will not be aborted.
function record_async_signal { sig=$1; delay_secs=$2; exe=$3; exeargs=$4;
    delay_kill $sig $delay_secs $exe-$nonce &
    record $exe $exeargs
    wait
}

function replay { replayflags=$1
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT replay.err \
        $RR_EXE $GLOBAL_OPTIONS replay $UNBOUND_OPTION --retry-transient-errors -a \
        $replayflags 1> replay.out 2> replay.err
}

function rerun { rerunflags=$1
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT rerun.err \
        $RR_EXE $GLOBAL_OPTIONS rerun $rerunflags 1> rerun.out 2> rerun.err
}

function pack {
    _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT pack.err \
        $RR_EXE $GLOBAL_OPTIONS pack $@ 1> pack.out 2> pack.err
}

function do_ps { psflags=$1
    _RR_TRACE_DIR="$workdir" \
        $RR_EXE $GLOBAL_OPTIONS ps $psflags
}

#  debug <expect-script-name> [replay-args]
function debug {
    debug_gdb_only $TEST_PREFIX$TESTNAME_NO_BITNESS
    if [[ "$test_passed" == "y" ]]; then
        debug_lldb_only $TEST_PREFIX$TESTNAME_NO_BITNESS
    fi
}

#  debug_lldb_only <expect-script-name> [replay-args]
#
# Load the "expect" script to drive replay of the recording of |exe|.
# Only LLDB is tested.
function debug_lldb_only { expectscript=$1; replayargs=$2
    RR_LOG_FILE=rr.log _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT test-monitor.output \
        python3 $TESTDIR/$expectscript.py --lldb \
        $RR_EXE $GLOBAL_OPTIONS replay $replayargs
    if [[ $? == 0 ]]; then
        passed_msg lldb
    else
        failed "debug script failed (lldb); see `pwd`/lldb_rr.log and `pwd`/test-monitor.output"
        echo "--------------------------------------------------"
        echo "rr.log:"
        cat rr.log
        echo "--------------------------------------------------"
    fi
}

#  debug_gdb_only <expect-script-name> [replay-args]
#
# Load the "expect" script to drive replay of the recording of |exe|.
# Only GDB is tested.
function debug_gdb_only { expectscript=$1; replayargs=$2
    RR_LOG_FILE=rr.log _RR_TRACE_DIR="$workdir" test-monitor $TIMEOUT test-monitor.output \
        python3 $TESTDIR/$expectscript.py \
        $RR_EXE $GLOBAL_OPTIONS replay $UNBOUND_OPTION -o-n -o-ix -o$TESTDIR/test_setup.gdb $replayargs
    if [[ $? == 0 ]]; then
        passed_msg gdb
    else
        failed "debug script failed (gdb); see `pwd`/gdb_rr.log and `pwd`/test-monitor.output"
        echo "--------------------------------------------------"
        echo "rr.log:"
        cat rr.log
        echo "--------------------------------------------------"
    fi
}

function failed { msg=$1;
    test_passed=n
    echo "Test '$TESTNAME' FAILED: $msg"
}

function passed {
    echo "Test '$TESTNAME' PASSED"
}

function passed_msg { msg=$1
    echo "Test '$TESTNAME' PASSED ($msg)"
}

function just_check_replay_err {
    if [[ $(cat replay.err) != "" ]]; then
        failed ": error during replay:"
        echo "--------------------------------------------------"
        cat replay.err
        echo "--------------------------------------------------"
        echo "replay.out:"
        echo "--------------------------------------------------"
        cat replay.out
        echo "--------------------------------------------------"
        return 1
    fi
    return 0
}

function just_check_record { token=$1;
     if [ ! -f record.out -o ! -f replay.err -o ! -f replay.out -o ! -f record.err ]; then
        failed "output files not found."
    elif [[ $(cat record.err) != "" ]]; then
        failed ": error during recording:"
        echo "--------------------------------------------------"
        cat record.err
        echo "--------------------------------------------------"
        echo "record.out:"
        echo "--------------------------------------------------"
        cat record.out
        echo "--------------------------------------------------"
    elif [[ "$token" != "" && "record.out" != $(grep -l "$token" record.out) ]]; then
        failed ": token '$token' not in record.out:"
        echo "--------------------------------------------------"
        cat record.out
        echo "--------------------------------------------------"
    else
        return 0;
    fi
    return 1
}

function just_check_record_replay_match {
    if [[ $(diff record.out replay.out) != "" ]]; then
        failed ": output from recording different than replay"
        echo "diff -U8 $workdir/record.out $workdir/replay.out"
        diff -U8 record.out replay.out
        return 1
    fi
    return 0
}

# Check that (i) no error during replay; (ii) recorded and replayed
# output match; (iii) the supplied token was found in the output.
# Otherwise the test fails.
function check { token=$1;
    if ! just_check_record $1; then return;
    elif ! just_check_replay_err; then return;
    elif ! just_check_record_replay_match; then return;
    else
        passed
    fi
}

# Like `check`, but omit the check that the output matches between record and
# replay
function check_record { token=$1;
    if ! just_check_record $token; then return;
    elif ! just_check_replay_err; then return;
    else
        passed
    fi
}

# Like `check`, but don't look at the record output at all
function check_replay_token { token=$1;
    if [[ "$token" != "" && "replay.out" != $(grep -l "$token" replay.out) ]]; then
        failed ": token '$token' not in replay.out:"
        echo "--------------------------------------------------"
        cat replay.out
        echo "--------------------------------------------------"
    elif ! just_check_replay_err; then return;
    else
        passed
    fi
}


#  compare_test <token> [<replay-flags>] [executable]
#
# Record the test name passed to |util.sh|, then replay it (optionally
# with $replayflags) and verify record/replay output match and $token
# appears in the output. Uses $executable instead of the passed-in testname
# if present.
function compare_test { token=$1; replayflags=$2;
    test=$TESTNAME
    if (( $# >= 3 )); then
        test=$3
    fi
    if [[ $token == "" ]]; then
        failed ": didn't pass an exit token"
    fi
    record $test
    replay $replayflags
    check $token
}

#  debug_test
#
# Record the test name passed to |util.sh|, then replay the recording
# using the "expect" script $test-name.py, which is responsible for
# computing test pass/fail.
function debug_test {
    record $TESTNAME
    debug
}

#  debug_test_gdb_only
#
# Record the test name passed to |util.sh|, then replay the recording
# using the "expect" script $test-name.py, which is responsible for
# computing test pass/fail. Only GDB is tested.
function debug_test_gdb_only {
    record $TESTNAME
    debug_gdb_only $TEST_PREFIX$TESTNAME_NO_BITNESS
}

#  rerun_singlestep_test
#
# Record the test name passed to |util.sh|, then rerun --singlestep
# the recording.
function rerun_singlestep_test {
    record $TESTNAME
    rerun $UNBOUND_OPTION "--singlestep=rip,gp_x16,flags"
}

# Return an rr dump result of the most recent local recording.
function get_events {
    $RR_EXE $GLOBAL_OPTIONS dump "$@" latest-trace
}

# Return the number of events in the most recent local recording.
function count_events {
    local events=$(get_events -r | wc -l)
    # The |simple| test is just about the simplest possible C program,
    # and has around 180 events (when recorded on a particular
    # developer's machine).  If we count a number of events
    # significantly less than that, almost certainly something has gone
    # wrong.
    if [ "$events" -le 150 ]; then
        failed ": Recording had too few events.  Is |rr dump -r| broken?"
    fi
    # This event count is used to loop over attaching the debugger.
    # The tests assume that the debugger can be attached at all
    # events, but at the very last events, EXIT and so forth, rr can't
    # attach the debugger.  So we fudge the event count down to avoid
    # that edge case.
    let "events -= 10"
    echo $events
}

# Return a random number from the range [min, max], inclusive.
function rand_range { min=$1; max=$2
    local num=$RANDOM
    local range=""
    let "range = 1 + $max - $min"
    let "num %= $range"
    let "num += $min"
    echo $num
}

# Record |exe|, then replay it using the |restart_finish| debugger
# script attaching at every recorded event.  To make the
# debugger-replays more practical, the events are strided between at a
# random interval between [min, max], inclusive.
#
# So for example, |checkpoint_test simple 3 5| means to record the
# "simple" test, and attach the debugger at every X'th event, where X
# is a random number in [3, 5].
function checkpoint_test { exe=$1; min=$2; max=$3;
    record $exe
    num_events=$(count_events)
    stride=$(rand_range $min $max)
    for i in $(seq 1 $stride $num_events); do
        echo Checkpointing at event $i ...
        debug_gdb_only restart_finish "-g $i"
        if [[ "$test_passed" != "y" ]]; then
            break
        fi
    done
}

function wait_for_complete {
    local record_dir=${1:-"${workdir}/latest-trace"}
    for ((i = 0; i < $TIMEOUT * 10; i++)); do
        [[ -f "$record_dir/incomplete" ]] || break
        sleep 0.1
    done
}

# If not given by user, try to find out if C.UTF-8 or en_US.UTF-8 is available, if not use any UTF-8 locale.
function set_utf_locale {
    unset LC_ALL
    if [ -z "$(which locale)" ]; then
        if [ -z "$LC_ALL" ]; then export LC_ALL=en_US.UTF-8; fi
    else
        if [ -z "$LC_ALL" ]; then export LC_ALL=$(locale -a | grep -i -E "C\.utf.*8" | head -n1); fi
        if [ -z "$LC_ALL" ]; then export LC_ALL=$(locale -a | grep -i -E "en_US\.utf.*8" | head -n1); fi
        if [ -z "$LC_ALL" ]; then export LC_ALL=$(locale -a | grep -i -E ".*\.utf.*8" | head -n1); fi
        if [ -z "$LC_ALL" ]; then
            echo "Warning: no UTF-8 locale found."
        else
            echo "Using LC_ALL=$LC_ALL"
        fi
    fi
}
