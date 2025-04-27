cmake_minimum_required(VERSION 3.20)
project(software-counters)

find_package(LLVM CONFIG)
include_directories(../../src/preload/)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused-variable")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-variable")

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a+lse -mno-outline-atomics")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a+lse -mno-outline-atomics")
endif()

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
set(CMAKE_CXX_STANDARD 17 CACHE STRING "")

if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

add_library(SoftwareCountersClang SHARED SoftwareCounters.cpp)

set(SC_COMMON_FLAGS "-O0 -g -fpass-plugin=${CMAKE_CURRENT_BINARY_DIR}/libSoftwareCountersClang.so")

set(INSTRUMENT_THESE
    testCounter
    testSimpleCounter
   )

foreach( instrument_this ${INSTRUMENT_THESE} )
    add_executable(${instrument_this} "${instrument_this}.c")
    set_source_files_properties("${instrument_this}.c" PROPERTIES
                                COMPILE_FLAGS ${SC_COMMON_FLAGS}
                                OBJECT_DEPENDS SoftwareCountersClang)

    add_custom_target("${instrument_this}.ll"
                      COMMENT "Generating ${instrument_this}.ll"
                      COMMAND ${CMAKE_C_COMPILER}
                              -I${CMAKE_CURRENT_SOURCE_DIR}/../../src/preload/
                              -S -emit-llvm
                              -o ${CMAKE_CURRENT_BINARY_DIR}/"${instrument_this}.ll"
                              ${CMAKE_CURRENT_SOURCE_DIR}/"${instrument_this}.c"
                      DEPENDS ${instrument_this})

    add_custom_target("${instrument_this}Opt.ll"
                      COMMENT "Generating ${instrument_this}Opt.ll"
                      COMMAND opt
                              -load-pass-plugin=${CMAKE_CURRENT_BINARY_DIR}/libSoftwareCountersClang.so
                              -S -passes="software-counters"
                              -o ${CMAKE_CURRENT_BINARY_DIR}/"${instrument_this}Opt.ll"
                              ${CMAKE_CURRENT_BINARY_DIR}/"${instrument_this}.ll"
                      DEPENDS SoftwareCounters "${instrument_this}.ll")

    add_custom_target("${instrument_this}_test_soft_rr"
                      COMMENT "Testing software counters record and replay of ${instrument_this}"
                      COMMAND echo "---- RECORD ------------------------------------------------"
                      COMMAND rr record --log=all:info --scs=never-jii -n -W -- ${CMAKE_CURRENT_BINARY_DIR}/${instrument_this}
                      COMMAND echo "---- REPLAY ------------------------------------------------"
                      COMMAND rr replay -W -a
                      COMMAND echo "---- Completed record and replay ---------------------------"
                      DEPENDS ${instrument_this})
endforeach()
