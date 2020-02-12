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

qt5_generate_dbus_interface(firewalld.h
  firewalld.xml
  )
qt5_add_dbus_adaptor(firewalld_plugin_interface_SRCS
  firewalld.xml
  firewalld.h
  firewalld
  )

set(firewalld_plugin_helper_SRCS helper.cpp ${CMAKE_CURRENT_BINARY_DIR}/firewalld.xml )


add_executable(kde_firewalld_plugin_interface ${firewalld_plugin_helper_SRCS})



# set_target_properties(kcm_firewalld_helper PROPERTIES OUTPUT_NAME kcm_firewalld_helper)
target_link_libraries(kde_firewalld_plugin_interface Qt5::Core KF5::Auth Qt5::DBus)
#if (IS_ABSOLUTE "${LIBEXEC_INSTALL_DIR}")
  #set(FIREWALLD_PLUGIN_HELPER_PATH ${LIBEXEC_INSTALL_DIR}/kde_firewalld_plugin_interface.py)
#else()
  #set(FIREWALLD_PLUGIN_HELPER_PATH ${CMAKE_INSTALL_PREFIX}/${LIBEXEC_INSTALL_DIR}/kde_firewalld_plugin_interface.py)
#endif()
#configure_file(kcm_firewalld_helper.py.cmake ${CMAKE_BINARY_DIR}/kde_firewalld_plugin_interface.py)
configure_file(firewalld_interface_config.h.cmake ${CMAKE_BINARY_DIR}/firewalld_interface_config.h)

kauth_install_actions(org.kde.firewalld org.kde.firewalld.actions)
install(TARGETS kde_firewalld_plugin_interface DESTINATION ${KAUTH_HELPER_INSTALL_DIR})
kauth_install_helper_files(kde_firewalld_plugin_interface org.kde.firewalld root)

# install(TARGETS kcm_firewalld_helper DESTINATION ${LIBEXEC_INSTALL_DIR})
#install(PROGRAMS ${CMAKE_BINARY_DIR}/kde_firewalld_plugin_interface.py DESTINATION ${LIBEXEC_INSTALL_DIR})

# configure_file(org.kde.firewalld.service.cmake ${CMAKE_CURRENT_BINARY_DIR}/session/org.kde.firewalld.service)
# install(FILES ${CMAKE_CURRENT_BINARY_DIR}/session/org.kde.firewalld.service DESTINATION ${DBUS_SERVICES_INSTALL_DIR})
install(FILES defaults DESTINATION ${DATA_INSTALL_DIR}/kcm_firewalld)
