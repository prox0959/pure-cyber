cmake_minimum_required(VERSION 3.16)
project(PureCyber CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
#  CMakeLists.txt — PureCyber Build Sistemi
#
#  KURULUM:
#  1. Npcap SDK'yı indir: https://npcap.com/#download
#     → "Npcap SDK" kısmından zip'i indir
#  2. Zip'i açıp bu klasöre koy → npcap-sdk/
#     Klasör yapısı:
#       pure cyber/
#         npcap-sdk/
#           Include/
#             pcap.h
#             ...
#           Lib/
#             x64/
#               wpcap.lib
#               Packet.lib
#
#  BUILD:
#    mkdir build
#    cd build
#    cmake .. -A x64
#    cmake --build . --config Release
#
#  Çıktı: build/Release/purecyber.exe
# ============================================================

# ─── Npcap SDK yolları ─────────────────────────────────────
set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk")

if(NOT EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
    message(FATAL_ERROR
        "\n[PureCyber] Npcap SDK bulunamadı!\n"
        "  Lütfen https://npcap.com/#download adresinden SDK'yı indir\n"
        "  ve '${NPCAP_SDK_DIR}' klasörüne çıkart.\n"
        "  Beklenen dosya: ${NPCAP_SDK_DIR}/Include/pcap.h\n"
    )
endif()

include_directories("${NPCAP_SDK_DIR}/Include")

# x64 için lib yolu
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
else()
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
endif()

# ─── Source Files ──────────────────────────────────────────
add_executable(purecyber
    main.cpp
    src/display.cpp
    src/device_info.cpp
    src/parser.cpp
    src/tls_sniffer.cpp
    src/credential.cpp
    src/webhook.cpp
    src/capture.cpp
)

# ─── Include ───────────────────────────────────────────────
target_include_directories(purecyber PRIVATE
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_SOURCE_DIR}/src"
    "${NPCAP_SDK_DIR}/Include"
)

# ─── Libraries ─────────────────────────────────────────────
target_link_libraries(purecyber PRIVATE
    "${NPCAP_LIB_DIR}/wpcap.lib"
    "${NPCAP_LIB_DIR}/Packet.lib"
    ws2_32          # Winsock
    wininet         # WinINet (webhook için)
    iphlpapi        # IP Helper API
)

# ─── Windows defines ───────────────────────────────────────
target_compile_definitions(purecyber PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00   # Windows 10+
    WPCAP
    HAVE_REMOTE
)

# ─── Compiler flags ────────────────────────────────────────
if(MSVC)
    target_compile_options(purecyber PRIVATE
        /W3         # Warning level 3
        /O2         # Optimize for speed (Release)
        /utf-8      # UTF-8 kaynak dosyalar
    )
endif()

# ─── Release build info ────────────────────────────────────
message(STATUS "")
message(STATUS "=== PureCyber Build ===")
message(STATUS "  Npcap SDK : ${NPCAP_SDK_DIR}")
message(STATUS "  Lib Dir   : ${NPCAP_LIB_DIR}")
message(STATUS "  Platform  : ${CMAKE_GENERATOR_PLATFORM}")
message(STATUS "")
