add_executable(smbparser_tests
    test_types.cpp
    test_stream_reader.cpp
    test_smb1_structs.cpp
    test_smb1_packet.cpp
    test_smb2_packet.cpp
    test_parser.cpp
    test_file_assembler.cpp
    test_integration.cpp)
target_link_libraries(smbparser_tests PRIVATE smbparser GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(smbparser_tests)
