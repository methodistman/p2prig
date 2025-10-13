include(src/backend/cpu/cpu.cmake)
include(src/backend/opencl/opencl.cmake)
include(src/backend/cuda/cuda.cmake)
include(src/backend/common/common.cmake)
include(src/backend/remote/remote.cmake)


set(HEADERS_BACKEND
    "${HEADERS_BACKEND_COMMON}"
    "${HEADERS_BACKEND_CPU}"
    "${HEADERS_BACKEND_OPENCL}"
    "${HEADERS_BACKEND_CUDA}"
    "${HEADERS_BACKEND_REMOTE}"
   )

set(SOURCES_BACKEND
    "${SOURCES_BACKEND_COMMON}"
    "${SOURCES_BACKEND_CPU}"
    "${SOURCES_BACKEND_OPENCL}"
    "${SOURCES_BACKEND_CUDA}"
    "${SOURCES_BACKEND_REMOTE}"
   )
