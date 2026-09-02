#pragma once
// The flat JSON field scanner the VIRULE service clients use
// (press_activity_service::detail in the VIRULE repository, ported
// byte-for-byte). It is deliberately NOT a JSON parser: every wire value it
// reads is grammar-checked opaque hex, a canonical UTC instant, or a
// control-character-stripped display label, so a marker scan is exact.

#include <string>

namespace vclient::json_scan {

inline bool find_string_in(const std::string& text, size_t begin, size_t end,
                           const char* name, std::string& out) {
    const std::string marker = std::string("\"") + name + "\":\"";
    const size_t at = text.find(marker, begin);
    if (at == std::string::npos || at >= end) return false;
    const size_t vb = at + marker.size();
    const size_t ve = text.find('"', vb);
    if (ve == std::string::npos || ve > end) return false;
    out = text.substr(vb, ve - vb);
    return true;
}

inline bool find_number_in(const std::string& text, size_t begin, size_t end,
                           const char* name, long long& out) {
    const std::string marker = std::string("\"") + name + "\":";
    const size_t at = text.find(marker, begin);
    if (at == std::string::npos || at >= end) return false;
    size_t p = at + marker.size();
    bool any = false;
    long long v = 0;
    while (p < end && text[p] >= '0' && text[p] <= '9') {
        v = v * 10 + (text[p] - '0');
        ++p;
        any = true;
    }
    if (!any) return false;
    out = v;
    return true;
}

// Minimal JSON string escaping for free-text display labels (the
// qa_access_service::detail::json_escape port).
inline std::string json_escape(const std::string& s) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 8);
    for (const char raw : s) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += kHex[(c >> 4) & 0xF];
                    out += kHex[c & 0xF];
                } else {
                    out += raw;
                }
        }
    }
    return out;
}

} // namespace vclient::json_scan
