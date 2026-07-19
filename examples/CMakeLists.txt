# Example programs. Each is a standalone translation unit that only
# includes <epx/epx.hpp> — none of them need to know EPX's internal src/
# layout, matching what a real consumer of the library would do.

add_executable(expose_demo expose_demo.cpp)
target_link_libraries(expose_demo PRIVATE epx::epx)

add_executable(client_demo client_demo.cpp)
target_link_libraries(client_demo PRIVATE epx::epx)

add_executable(chat chat.cpp)
target_link_libraries(chat PRIVATE epx::epx)

# groupchat_common.hpp is shared, header-only, app-level plumbing (not part
# of the library) — see its header comment for the design.
add_executable(groupchat_room groupchat_room.cpp groupchat_common.hpp)
target_link_libraries(groupchat_room PRIVATE epx::epx)

add_executable(groupchat groupchat.cpp groupchat_common.hpp)
target_link_libraries(groupchat PRIVATE epx::epx)

# Serverless polyglot group chat — see the file header for the convention
# every language repo's port shares.
add_executable(polychat polychat.cpp)
target_link_libraries(polychat PRIVATE epx::epx)

# FlatBuffers demo host (docs/SERIALIZATION.md): built only when the
# FlatBuffers headers are present — the schema-generated header is
# checked in, so flatc itself isn't needed to build.
find_path(EPX_FLATBUFFERS_INCLUDE flatbuffers/flatbuffers.h)
if(EPX_FLATBUFFERS_INCLUDE)
    add_executable(search_host flatbuffers_demo/search_host.cpp)
    target_include_directories(search_host PRIVATE ${EPX_FLATBUFFERS_INCLUDE} flatbuffers_demo)
    target_link_libraries(search_host PRIVATE epx::epx)
endif()

# C editions of the demos, built against the C ABI exactly the way a
# language binding consumer would. chat_c is the reference every
# binding's chat port mirrors (same endpoints, same envelope).
if(EPX_BUILD_CAPI)
    foreach(cex expose_demo_c client_demo_c chat_c polychat_c)
        add_executable(${cex} ${cex}.c)
        target_link_libraries(${cex} PRIVATE epx::epx_c)
    endforeach()
endif()
