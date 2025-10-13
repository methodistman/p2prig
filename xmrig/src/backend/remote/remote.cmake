if (WITH_REMOTE)
    add_definitions(/DXMRIG_FEATURE_REMOTE)

    set(HEADERS_BACKEND_REMOTE
        src/backend/remote/RemoteBackend.h
    )

    set(SOURCES_BACKEND_REMOTE
        src/backend/remote/RemoteBackend.cpp
    )
else()
    remove_definitions(/DXMRIG_FEATURE_REMOTE)
    set(HEADERS_BACKEND_REMOTE "")
    set(SOURCES_BACKEND_REMOTE "")
endif()
