set(INCLUDES
        "."
)

set(SOURCES
        "main.c"
)

# QUIC client example, see components/scion_quic
if (CONFIG_CSNET_QUIC)
    list(APPEND SOURCES "../../examples/simple_quic_client.c")
    list(APPEND INCLUDES "../../examples")
endif ()

idf_component_register(SRCS ${SOURCES}
        INCLUDE_DIRS ${INCLUDES})

spiffs_create_partition_image(storage ../spiffs_partition FLASH_IN_PROJECT)
