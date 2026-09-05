#pragma once
// VIRULE Client version. One place; the .rc files and the bridge status
// response all read these. Virule-Setup.exe's FILEVERSION/PRODUCTVERSION
// track the client release they ship with (owner decision 2026-09-04), so
// a Setup rebuilt for this release reports the same numbers.
#define VIRULE_CLIENT_VERSION_MAJOR 0
#define VIRULE_CLIENT_VERSION_MINOR 6
#define VIRULE_CLIENT_VERSION_PATCH 5
#define VIRULE_CLIENT_VERSION_STRING "0.6.5"
#define VIRULE_CLIENT_VERSION_WSTRING L"0.6.5"
