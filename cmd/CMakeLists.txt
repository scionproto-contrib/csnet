add_executable(ping ping.c)
target_link_libraries(ping PRIVATE scion)

# install ping binary
install(TARGETS ping)