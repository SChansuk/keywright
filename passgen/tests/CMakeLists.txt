find_package(Catch2 3 CONFIG REQUIRED)
include(Catch)

add_executable(passgen_tests "credgen_tests.cpp" "../credgen.cpp" "keyfile_tests.cpp" "../keyfile.cpp")
target_include_directories(passgen_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(passgen_tests PRIVATE
	keywright::secrets
	keywright::platform
	unofficial-sodium::sodium
	Catch2::Catch2WithMain)
set_property(TARGET passgen_tests PROPERTY CXX_STANDARD 20)

catch_discover_tests(passgen_tests)
