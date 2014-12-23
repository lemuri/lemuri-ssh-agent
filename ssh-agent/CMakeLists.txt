include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set(ssh_agent_SRCS
    sshagent.cpp
    main.cpp
)

add_executable(lemuri-ssh-agent ${ssh_agent_SRCS})

qt5_use_modules(lemuri-ssh-agent Core Network)

install(TARGETS lemuri-ssh-agent DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
