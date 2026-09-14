cmake_minimum_required(VERSION 3.16)
project(wlan_feature_validator VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(wlan-analyzer src/main.cpp)

if(MSVC)
  target_compile_options(wlan-analyzer PRIVATE /W4 /permissive-)
else()
  target_compile_options(wlan-analyzer PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

enable_testing()
find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_test(
  NAME wlan_python_validation
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/automation/validate.py
)

add_test(
  NAME wlan_unit_tests
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/test_wlan_model.py
)
