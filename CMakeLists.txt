cmake_minimum_required(VERSION 3.10)
project(executor)
set(CMAKE_CXX_STANDARD 17)
add_library(executor SHARED main.cpp)

include(FetchContent)
FetchContent_Declare(websocketpp GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git GIT_TAG master)
FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3)
FetchContent_MakeAvailable(websocketpp nlohmann_json)

target_include_directories(executor PRIVATE ${websocketpp_SOURCE_DIR} ${nlohmann_json_SOURCE_DIR}/include)
target_link_libraries(executor log)