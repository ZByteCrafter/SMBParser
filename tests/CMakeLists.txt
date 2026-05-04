add_executable(smbparser_tests
    test_types.cpp)
target_link_libraries(smbparser_tests PRIVATE smbparser GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(smbparser_tests)
