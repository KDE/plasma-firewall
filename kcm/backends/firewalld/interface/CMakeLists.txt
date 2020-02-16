# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(${CMAKE_BINARY_DIR})

# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)

find_package(Qt5 ${QT_MIN_VERSION} CONFIG REQUIRED COMPONENTS
    Quick
    X11Extras
    DBus
)



find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
    I18n
    Auth
)

set(firewalld_plugin_helper_SRCS helper.cpp)


add_executable(kde_firewalld_plugin_interface ${firewalld_plugin_helper_SRCS})


target_link_libraries(kde_firewalld_plugin_interface Qt5::Core KF5::Auth Qt5::DBus)
