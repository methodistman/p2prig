if (WITH_MARKET)
    add_definitions(/DXMRIG_FEATURE_MARKET)

    set(HEADERS_MARKET
        src/market/Market.h
    )

    set(SOURCES_MARKET
        src/market/Market.cpp
    )
else()
    remove_definitions(/DXMRIG_FEATURE_MARKET)
    set(HEADERS_MARKET "")
    set(SOURCES_MARKET "")
endif()
