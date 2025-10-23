if (WITH_PEER)
    add_definitions(/DXMRIG_FEATURE_PEER)

    set(HEADERS_PEER
        src/peer/PeerServer.h
        src/peer/PeerConfig.h
        src/peer/ScratchpadAllocator.h
        src/peer/PeerSession.h
    )

    set(SOURCES_PEER
        src/peer/PeerServer.cpp
        src/peer/ScratchpadAllocator.cpp
        src/peer/PeerSession.cpp
    )
else()
    remove_definitions(/DXMRIG_FEATURE_PEER)
    set(HEADERS_PEER "")
    set(SOURCES_PEER "")
endif()
