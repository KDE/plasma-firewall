add_executable(ipvalidatortest ipvalidatortest.cpp)
target_link_libraries(ipvalidatortest kcm_firewall_core Qt::Test)
add_test(NAME ipvalidatortest COMMAND ipvalidatortest)

add_test(NAME kcm_smoketest COMMAND kcmshell6 --smoke-test kcm_firewall)
set_tests_properties(kcm_smoketest PROPERTIES
    ENVIRONMENT_MODIFICATION QT_PLUGIN_PATH=path_list_prepend:${CMAKE_BINARY_DIR}/bin
)
