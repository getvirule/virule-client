#pragma once
// HTTPS POST helper for the VIRULE API, ported from the product's
// press_key_service::detail::https_post_json: WinHTTP, TLS validation ON
// (the WinHTTP default), bounded response, the same timeout posture. The
// client talks to api.virule.app and nothing else.

#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace vclient::http {

inline bool https_post_json(const wchar_t* host, const wchar_t* path, const std::string& body,
                            unsigned long& status_out, std::string& body_out) {
    status_out = 0;
    body_out.clear();
    HINTERNET hsession = WinHttpOpen(L"ViruleClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hsession) return false;
    WinHttpSetTimeouts(hsession, 5000, 5000, 15000, 20000);
    bool ok = false;
    HINTERNET hconnect = WinHttpConnect(hsession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hconnect) {
        HINTERNET hrequest = WinHttpOpenRequest(hconnect, L"POST", path, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (hrequest) {
            static const wchar_t* kHeaders = L"Content-Type: application/json\r\n";
            if (WinHttpSendRequest(hrequest, kHeaders, static_cast<DWORD>(-1L),
                    const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                    static_cast<DWORD>(body.size()), 0) &&
                WinHttpReceiveResponse(hrequest, nullptr)) {
                DWORD status = 0;
                DWORD sz = sizeof(status);
                if (WinHttpQueryHeaders(hrequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX)) {
                    status_out = status;
                    ok = true;
                }
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(hrequest, &avail) && avail > 0) {
                    if (body_out.size() + avail > 16 * 1024) break;
                    std::string chunk(avail, '\0');
                    DWORD read = 0;
                    if (!WinHttpReadData(hrequest, chunk.data(), avail, &read) || read == 0) break;
                    body_out.append(chunk.data(), read);
                }
            }
            WinHttpCloseHandle(hrequest);
        }
        WinHttpCloseHandle(hconnect);
    }
    WinHttpCloseHandle(hsession);
    return ok;
}

} // namespace vclient::http
