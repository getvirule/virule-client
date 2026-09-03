#pragma once
// HTTP helpers for the VIRULE services: the HTTPS POST ported from the
// product's press_key_service::detail::https_post_json (WinHTTP, TLS
// validation ON - the WinHTTP default - bounded response, the same timeout
// posture), plus the bounded GET Virule-Setup uses to fetch the release
// manifest and the client binary from downloads.virule.app. Every response
// is size-capped by the caller; nothing here ever writes a file.

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

// Bounded GET. `max_bytes` is a hard cap the caller derives from a trusted
// expectation (the manifest cap, or the manifest's own declared size for the
// binary); a response that runs past it fails rather than truncates, so a
// caller can never mistake a clipped body for a complete one. `secure`
// exists only for the development seam (--manifest-url= against a local
// server); production callers always pass true.
inline bool http_get(const wchar_t* host, unsigned short port, bool secure,
                     const wchar_t* path, size_t max_bytes,
                     unsigned long& status_out, std::string& body_out) {
    status_out = 0;
    body_out.clear();
    HINTERNET hsession = WinHttpOpen(L"ViruleSetup/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hsession) return false;
    WinHttpSetTimeouts(hsession, 10000, 10000, 15000, 30000);
    bool ok = false;
    bool overflow = false;
    HINTERNET hconnect = WinHttpConnect(hsession, host, port, 0);
    if (hconnect) {
        HINTERNET hrequest = WinHttpOpenRequest(hconnect, L"GET", path, nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            secure ? WINHTTP_FLAG_SECURE : 0);
        if (hrequest) {
            if (WinHttpSendRequest(hrequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hrequest, nullptr)) {
                DWORD status = 0;
                DWORD sz = sizeof(status);
                if (WinHttpQueryHeaders(hrequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX)) {
                    status_out = status;
                    ok = true;
                }
                if (max_bytes > 0) body_out.reserve(max_bytes < (1u << 20) ? max_bytes : (1u << 20));
                DWORD avail = 0;
                while (WinHttpQueryDataAvailable(hrequest, &avail) && avail > 0) {
                    if (body_out.size() + avail > max_bytes) { overflow = true; break; }
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
    if (overflow) {
        body_out.clear();
        return false;
    }
    return ok;
}

// GET https://<host>/<path> - the production form.
inline bool https_get(const wchar_t* host, const wchar_t* path, size_t max_bytes,
                      unsigned long& status_out, std::string& body_out) {
    return http_get(host, INTERNET_DEFAULT_HTTPS_PORT, true, path, max_bytes,
                    status_out, body_out);
}

} // namespace vclient::http
