project(passgen)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

add_executable(${PROJECT_NAME} "passgen.cpp" "passgen.h" "credgen.cpp" "credgen.h" "setup.cpp" "setup.h" "keyfile.h" "keyfile.cpp")
target_link_libraries(${PROJECT_NAME} PRIVATE 
	keywright::secrets
	keywright::platform
	keywright::config
	unofficial-sodium::sodium
	CLI11::CLI11
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET passgen PROPERTY CXX_STANDARD 20)
endif()

if (BUILD_TESTING)
  add_subdirectory(tests)
endif()
