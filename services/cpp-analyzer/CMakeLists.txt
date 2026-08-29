cmake_minimum_required(VERSION 3.16)
project(cpp_analyzer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GRPC REQUIRED grpc++)
pkg_check_modules(PROTOBUF REQUIRED protobuf)

find_program(PROTOC_EXECUTABLE protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

set(PROTO_DIR $ENV{PROTO_DIR})
if(NOT PROTO_DIR)
    set(PROTO_DIR ${CMAKE_SOURCE_DIR}/../../proto)
endif()
set(GENERATED_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

set(PROTO_SRCS ${GENERATED_DIR}/analyzer.pb.cc)
set(PROTO_HDRS ${GENERATED_DIR}/analyzer.pb.h)
set(GRPC_SRCS ${GENERATED_DIR}/analyzer.grpc.pb.cc)
set(GRPC_HDRS ${GENERATED_DIR}/analyzer.grpc.pb.h)

add_custom_command(
    OUTPUT ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
    COMMAND ${PROTOC_EXECUTABLE}
    ARGS --cpp_out=${GENERATED_DIR}
         --grpc_out=${GENERATED_DIR}
         --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
         -I ${PROTO_DIR}
         ${PROTO_DIR}/analyzer.proto
    DEPENDS ${PROTO_DIR}/analyzer.proto
)

add_executable(cpp-analyzer
    src/main.cpp
    ${PROTO_SRCS}
    ${GRPC_SRCS}
)

target_include_directories(cpp-analyzer PRIVATE ${GENERATED_DIR} ${GRPC_INCLUDE_DIRS} ${PROTOBUF_INCLUDE_DIRS})
target_link_libraries(cpp-analyzer PRIVATE ${GRPC_LIBRARIES} ${PROTOBUF_LIBRARIES} grpc++_reflection)
target_compile_options(cpp-analyzer PRIVATE ${GRPC_CFLAGS_OTHER})
