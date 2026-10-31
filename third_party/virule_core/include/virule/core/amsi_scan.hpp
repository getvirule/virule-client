#pragma once
// THE AMSI COMPATIBILITY PATH of evaluation scanning (owner decisions
// 2026-10-30, VIRULE/docs/specs/evaluation-security.md "Antivirus"): a
// NARROW path for a third-party antimalware provider that VIRULE has
// EXPLICITLY VALIDATED, used only when Microsoft Defender Antivirus is not
// the active antivirus (malware_scan.hpp keeps Defender, through its own
// command line tool, as the primary path). Header only, included by
// malware_scan.hpp, vendored byte-identical into virule-client as it is.
//
// SUPPORTED WINDOWS API ONLY (Microsoft Learn, "Antimalware Scan Interface
// (AMSI)"; the AmsiStream sample in microsoft/Windows-classic-samples): the
// documented consumer interface IAntimalware (CLSID CAntimalware, amsi.dll),
// IAntimalware::Scan of an IAmsiStream that VIRULE implements over the file,
// and the IAntimalwareProvider it returns, read for its DisplayName. VIRULE
// never instantiates a provider itself (IAntimalwareProvider is the
// interface amsi.dll calls; an application calling it directly skips
// amsi.dll's own loading and is not a documented use), never splits a file
// into pieces (no documented behaviour covers fragments), and never writes
// AMSI's settings (FeatureBits included).
//
// MEASURED (Windows 10 19045, Defender platform 4.18.26100.4, standard user,
// 2026-10-30; VIRULE/docs/reviews/EVAL_SECURITY_POLICY_AMSI_2026-10-30.md):
// Defender's own provider (MpOav.dll) reads a file of up to 16,777,216 bytes
// in one Read and answers 1; at 16,777,217 bytes and above it answers
// E_INVALIDARG with NO Read at all AND still writes 1 (NOT_DETECTED) into
// the result. So a result is read only after S_OK, the result starts as a
// non-clean value, and "clean" also needs the stream's own record that every
// byte was delivered. An in-memory EICAR answers 32768.
//
// IDENTITY IS THE SIGNED PROVIDER DLL, not a name. A provider is registered
// under HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}; its in-process server
// is read from HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32 in this
// process's own registry view (never the merged HKCR view a user could
// shadow); the DLL's Authenticode signature is verified by VIRULE
// (WinVerifyTrust, embedded signature) and its signer and file version read.
// DisplayName is what the provider says about itself: a cross-check, never
// identity. After the scan the DLL loaded in this process must be that same
// verified file.
//
// THE RULES (WORKING CHOICES drawn from the owner's fail-closed decisions,
// PENDING OWNER REVIEW; evaluation-security.md):
//   - exactly ONE provider registered. With several, every Read reaches the
//     one stream and cannot be traced to a provider (one that is not allowed
//     could read everything while the allowed one read nothing), and how
//     amsi.dll combines several providers' answers is not documented.
//   - that provider matches an ALLOWLIST entry (CLSID, signer, display name,
//     a file-version range) and no DENYLIST entry (the denylist wins).
//     Unknown, unidentifiable, unsigned or failing = unsupported.
//   - a file is CLEAN only when Scan returned S_OK, the result is 0 or 1
//     (AMSI_RESULT_CLEAN, AMSI_RESULT_NOT_DETECTED), the returned provider's
//     DisplayName matches, VIRULE's stream served every byte of the file
//     (the UNION of [position, position + bytes read) covers [0, size)), no
//     Read of VIRULE's own failed, and the file's size and write time are
//     unchanged. AmsiResultIsMalware (32768 and above) is DETECTED. 2 to
//     32767 (the provider's "estimated risk", the BLOCKED_BY_ADMIN range
//     inside it) is never clean. Anything else is INCOMPLETE.
//   - coverage proves the bytes were DELIVERED to the provider, not that it
//     inspected them; that is what a provider's qualification establishes
//     (tests/amsi_qualification), never this check alone.
//
// THE SHIPPED ALLOWLIST IS EMPTY: no third-party provider has been
// validated (none was available to test), and Defender's own provider is
// not used through AMSI (Defender active is the primary path; Defender's
// provider also fails the large-file criterion at 16 MiB). So today this
// path identifies the configuration and refuses it, recommending Microsoft
// Defender. A provider is added only from a passing qualification record.

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>
#include <amsi.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")
#endif

namespace virule::core::amsi_scan {

namespace fs = std::filesystem;

// ---------------------------------------------------------------- policy ----

/** A file version a.b.c.d, compared part by part. */
struct Version {
    std::uint16_t part[4] = {0, 0, 0, 0};
    bool operator<(const Version& o) const {
        for (int i = 0; i < 4; ++i) if (part[i] != o.part[i]) return part[i] < o.part[i];
        return false;
    }
    bool operator==(const Version& o) const {
        for (int i = 0; i < 4; ++i) if (part[i] != o.part[i]) return false;
        return true;
    }
};

inline std::string version_text(const Version& v) {
    return std::to_string(v.part[0]) + "." + std::to_string(v.part[1]) + "." + std::to_string(v.part[2]) + "." + std::to_string(v.part[3]);
}

/** What VIRULE established about a registered provider (header). */
struct Identity {
    std::string clsid;           // "{...}" upper case, as registered
    std::string dll;             // the in-process server (UTF-8)
    bool signature_valid = false;
    std::string signer;          // the leaf certificate's simple name
    bool version_known = false;
    Version file_version;
    std::string display_name;    // from the returned provider, after a scan
};

/** One allowlist or denylist entry. Empty strings match nothing (an entry
 *  always names its CLSID and signer); the version range is [min, below). */
struct PolicyEntry {
    std::string clsid;
    std::string signer;
    std::string display_name;    // the allowlist checks it; "" in a denylist entry = any
    Version min_version;         // inclusive
    Version below_version;       // exclusive; all zero = no upper bound
    std::string evidence;        // the qualification record (allowlist) or reason (denylist)
};

struct Policy {
    std::vector<PolicyEntry> allow;
    std::vector<PolicyEntry> deny;
};

/** THE SHIPPED POLICY: no provider validated, nothing revoked (header). An
 *  entry is added only from a passing tests/amsi_qualification record of
 *  that exact provider and version range; a revocation is a deny entry. */
inline const Policy& shipped_policy() {
    static const Policy p{};
    return p;
}

enum class Verdict { allowed, denied, unknown };

namespace detail {

inline std::string upper(std::string s) {
    for (auto& c : s) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return s;
}

inline bool in_range(const PolicyEntry& e, const Identity& id) {
    if (!id.version_known) return false;
    if (id.file_version < e.min_version) return false;
    const Version none{};
    if (!(e.below_version == none) && !(id.file_version < e.below_version)) return false;
    return true;
}

inline bool names(const PolicyEntry& e, const Identity& id, bool check_display) {
    if (e.clsid.empty() || e.signer.empty()) return false;
    if (upper(e.clsid) != upper(id.clsid) || e.signer != id.signer) return false;
    if (check_display && e.display_name != id.display_name) return false;
    return in_range(e, id);
}

} // namespace detail

/**
 * THE POLICY DECISION for one identified provider (pure; tested). The
 * DENYLIST WINS. Allowed needs a valid signature, a known version and an
 * allowlist entry naming its CLSID, signer, display name and version.
 * Anything else is unknown, which is unsupported.
 */
inline Verdict decide(const Policy& p, const Identity& id) {
    for (const auto& e : p.deny) {
        if (detail::upper(e.clsid) == detail::upper(id.clsid) && !e.signer.empty() && e.signer == id.signer &&
            (e.display_name.empty() || e.display_name == id.display_name) &&
            (detail::in_range(e, id) || !id.version_known)) return Verdict::denied;
    }
    if (!id.signature_valid || id.signer.empty() || !id.version_known) return Verdict::unknown;
    for (const auto& e : p.allow) if (detail::names(e, id, true)) return Verdict::allowed;
    return Verdict::unknown;
}

/** Is an allowlist entry possible for this provider before its display name
 *  is known (no scan yet)? The full decide() runs again after the scan. */
inline Verdict decide_before_scan(const Policy& p, const Identity& id) {
    for (const auto& e : p.deny) {
        if (detail::upper(e.clsid) == detail::upper(id.clsid) && !e.signer.empty() && e.signer == id.signer &&
            (detail::in_range(e, id) || !id.version_known)) return Verdict::denied;
    }
    if (!id.signature_valid || id.signer.empty() || !id.version_known) return Verdict::unknown;
    for (const auto& e : p.allow) if (detail::names(e, id, false)) return Verdict::allowed;
    return Verdict::unknown;
}

// -------------------------------------------------------------- coverage ----

/** The bytes VIRULE's stream actually served: the UNION of the ranges, so a
 *  range read twice never stands in for one never read (pure; tested). */
struct Coverage {
    std::map<std::uint64_t, std::uint64_t> ranges;   // position -> longest length served there
    std::uint64_t reads = 0;
    bool read_failed = false;

    void add(std::uint64_t position, std::uint64_t length) {
        if (length == 0) return;
        auto& e = ranges[position];
        if (length > e) e = length;
    }
    std::uint64_t covered() const {
        std::uint64_t total = 0, end = 0;
        for (const auto& [p, n] : ranges) {
            const std::uint64_t s = p > end ? p : end, e = p + n;
            if (e > s) total += e - s;
            if (e > end) end = e;
        }
        return total;
    }
    /** Every byte of [0, size) served, with nothing failed. */
    bool complete(std::uint64_t size) const {
        if (read_failed) return false;
        if (size == 0) return true;
        std::uint64_t end = 0;
        for (const auto& [p, n] : ranges) {
            if (p > end) return false;   // a gap
            if (p + n > end) end = p + n;
        }
        return end >= size;
    }
};

// ---------------------------------------------------------------- result ----

enum class FileOutcome { clean, detected, not_clean, incomplete };

inline const char* file_outcome_name(FileOutcome o) {
    switch (o) {
        case FileOutcome::clean: return "clean";
        case FileOutcome::detected: return "detected";
        case FileOutcome::not_clean: return "not_clean";
        case FileOutcome::incomplete: return "incomplete";
    }
    return "incomplete";
}

/** THE CLASSIFICATION of one Scan (pure; tested). `result` is only read
 *  when `hr` succeeded. */
inline FileOutcome classify(long hr, unsigned long result, bool provider_matches, bool coverage_complete, bool file_unchanged) {
    if (hr < 0) return FileOutcome::incomplete;          // FAILED(hr): result is meaningless (it reads 1 on a refusal)
    if (result >= 32768) return FileOutcome::detected;   // AmsiResultIsMalware
    if (!provider_matches) return FileOutcome::incomplete;
    if (result > 1) return FileOutcome::not_clean;       // an estimated risk, or blocked by an administrator
    if (!coverage_complete || !file_unchanged) return FileOutcome::incomplete;
    return FileOutcome::clean;
}

struct FileResult {
    std::string path;            // UTF-8
    std::uint64_t size = 0;
    FileOutcome outcome = FileOutcome::incomplete;
    long hr = 0;
    unsigned long result = 0;
    std::uint64_t covered = 0;
    std::string provider;        // the returned provider's DisplayName ("" = none)
};

/** Is the configuration usable, and which provider is it? */
struct Availability {
    bool usable = false;
    std::vector<Identity> providers;   // every registered provider, identified as far as possible
    std::string reason;                // technical, for the log; never shown
};

#if defined(_WIN32)
namespace detail {

inline std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

inline std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

/** The registered provider CLSIDs, in this process's registry view. */
inline std::vector<std::wstring> registered_clsids(bool& readable) {
    std::vector<std::wstring> out;
    HKEY k = nullptr;
    const LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI\\Providers", 0, KEY_READ, &k);
    readable = rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
    if (rc != ERROR_SUCCESS) return out;
    for (DWORD i = 0;; ++i) {
        wchar_t name[128];
        DWORD len = 128;
        const LONG e = RegEnumKeyExW(k, i, name, &len, nullptr, nullptr, nullptr, nullptr);
        if (e == ERROR_NO_MORE_ITEMS) break;
        if (e != ERROR_SUCCESS) { readable = false; break; }
        out.emplace_back(name, len);
    }
    RegCloseKey(k);
    return out;
}

/** The CLSID's in-process server, from HKLM's own Classes key (never HKCR). */
inline std::wstring inproc_server(const std::wstring& clsid) {
    const std::wstring key = L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";
    wchar_t buf[2048];
    DWORD bytes = sizeof buf;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), nullptr, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, nullptr, buf, &bytes) != ERROR_SUCCESS) return {};
    std::wstring p(buf);
    while (!p.empty() && (p.back() == L' ')) p.pop_back();
    if (p.size() >= 2 && p.front() == L'"') {
        const auto close = p.find(L'"', 1);
        p = close == std::wstring::npos ? std::wstring() : p.substr(1, close - 1);
    }
    return p;
}

/** WinVerifyTrust (embedded signature) and the leaf signer's simple name. */
inline bool verify_signer(const std::wstring& file, std::string& signer) {
    signer.clear();
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = file.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG st = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    bool ok = false;
    if (st == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(wd.hWVTStateData);
        CRYPT_PROVIDER_SGNR* sg = pd ? WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0) : nullptr;
        if (sg && sg->csCertChain > 0 && sg->pasCertChain && sg->pasCertChain[0].pCert) {
            wchar_t name[512];
            if (CertGetNameStringW(sg->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512) > 1) {
                signer = utf8(name);
                ok = true;
            }
        }
    }
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    return ok;
}

inline bool file_version_of(const std::wstring& file, Version& v) {
    DWORD ignored = 0;
    const DWORD n = GetFileVersionInfoSizeW(file.c_str(), &ignored);
    if (n == 0) return false;
    std::vector<unsigned char> buf(n);
    if (!GetFileVersionInfoW(file.c_str(), 0, n, buf.data())) return false;
    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&fixed), &len) || !fixed || len < sizeof(VS_FIXEDFILEINFO)) return false;
    v.part[0] = HIWORD(fixed->dwFileVersionMS);
    v.part[1] = LOWORD(fixed->dwFileVersionMS);
    v.part[2] = HIWORD(fixed->dwFileVersionLS);
    v.part[3] = LOWORD(fixed->dwFileVersionLS);
    return true;
}

/** VIRULE's IAmsiStream over one open file (Microsoft's AmsiStream sample
 *  pattern): CONTENT_SIZE, CONTENT_NAME, APP_NAME, SESSION; never
 *  CONTENT_ADDRESS (with it the provider could read memory VIRULE cannot
 *  observe). Every Read is recorded in the Coverage; nothing is held in
 *  memory beyond the provider's own buffer. `memory` serves a buffer
 *  instead (the qualification harness's EICAR, never written to disk). */
class Stream final : public IAmsiStream {
public:
    Stream(HANDLE file, std::uint64_t size, std::wstring name, Coverage* cov)
        : file_(file), size_(size), name_(std::move(name)), cov_(cov) {}
    Stream(const std::string* memory, std::wstring name, Coverage* cov)
        : memory_(memory), size_(memory->size()), name_(std::move(name)), cov_(cov) {}
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    STDMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IAmsiStream)) { *out = static_cast<IAmsiStream*>(this); AddRef(); return S_OK; }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&ref_)); }
    STDMETHODIMP_(ULONG) Release() override {
        const LONG n = InterlockedDecrement(&ref_);
        if (n == 0) delete this;
        return static_cast<ULONG>(n);
    }
    STDMETHODIMP GetAttribute(AMSI_ATTRIBUTE attribute, ULONG size, PBYTE buffer, PULONG used) override {
        if (!used || (!buffer && size > 0)) return E_INVALIDARG;
        *used = 0;
        static const wchar_t kApp[] = L"VIRULE";
        switch (attribute) {
            case AMSI_ATTRIBUTE_CONTENT_SIZE: { const ULONGLONG s = size_; return copy(&s, sizeof s, size, buffer, used); }
            case AMSI_ATTRIBUTE_CONTENT_NAME: return copy(name_.c_str(), (name_.size() + 1) * sizeof(wchar_t), size, buffer, used);
            case AMSI_ATTRIBUTE_APP_NAME: return copy(kApp, sizeof kApp, size, buffer, used);
            case AMSI_ATTRIBUTE_SESSION: { const HAMSISESSION none = nullptr; return copy(&none, sizeof none, size, buffer, used); }
            default: return E_NOTIMPL;
        }
    }
    STDMETHODIMP Read(ULONGLONG position, ULONG size, PBYTE buffer, PULONG read) override {
        if (!read || (!buffer && size > 0)) return E_INVALIDARG;
        *read = 0;
        ++cov_->reads;
        if (position >= size_) return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
        const ULONG want = static_cast<ULONG>(size_ - position < size ? size_ - position : size);
        if (memory_) {
            std::memcpy(buffer, memory_->data() + position, want);
            *read = want;
        } else {
            OVERLAPPED o{};
            o.Offset = static_cast<DWORD>(position & 0xffffffffu);
            o.OffsetHigh = static_cast<DWORD>(position >> 32);
            DWORD got = 0;
            if (!ReadFile(file_, buffer, want, &got, &o)) {
                cov_->read_failed = true;
                return HRESULT_FROM_WIN32(GetLastError());
            }
            *read = got;
            if (got != want) cov_->read_failed = true;   // a short read of a file that should hold these bytes
        }
        cov_->add(position, *read);
        return S_OK;
    }

private:
    ~Stream() = default;
    static HRESULT copy(const void* data, size_t n, ULONG size, PBYTE buffer, PULONG used) {
        *used = static_cast<ULONG>(n);
        if (size < n) return E_NOT_SUFFICIENT_BUFFER;
        std::memcpy(buffer, data, n);
        return S_OK;
    }
    LONG ref_ = 1;
    HANDLE file_ = nullptr;
    const std::string* memory_ = nullptr;
    std::uint64_t size_ = 0;
    std::wstring name_;
    Coverage* cov_ = nullptr;
};

/** COM for the calling thread, released only if this call initialized it. */
struct Com {
    bool owned = false;
    Com() { owned = SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)); }
    ~Com() { if (owned) CoUninitialize(); }
};

inline bool same_file(const std::wstring& a, const std::wstring& b) {
    std::error_code ec;
    return fs::equivalent(fs::path(a), fs::path(b), ec) && !ec;
}

/** The module the scan actually loaded is the verified DLL. */
inline bool loaded_is(const std::wstring& dll) {
    const HMODULE m = GetModuleHandleW(fs::path(dll).filename().c_str());
    if (!m) return false;
    wchar_t buf[4096];
    const DWORD n = GetModuleFileNameW(m, buf, 4096);
    return n > 0 && n < 4096 && same_file(std::wstring(buf, n), dll);
}

} // namespace detail

/** Every registered provider, identified as far as VIRULE can (header). */
inline std::vector<Identity> registered_providers(bool& readable) {
    std::vector<Identity> out;
    for (const auto& c : detail::registered_clsids(readable)) {
        Identity id;
        id.clsid = detail::upper(detail::utf8(c));
        const std::wstring dll = detail::inproc_server(c);
        wchar_t expanded[4096];
        const DWORD n = dll.empty() ? 0 : ExpandEnvironmentStringsW(dll.c_str(), expanded, 4096);
        const std::wstring path = n > 0 && n <= 4096 ? std::wstring(expanded) : dll;
        id.dll = detail::utf8(path);
        std::error_code ec;
        if (!path.empty() && fs::is_regular_file(fs::path(path), ec)) {
            id.signature_valid = detail::verify_signer(path, id.signer);
            id.version_known = detail::file_version_of(path, id.file_version);
        }
        out.push_back(std::move(id));
    }
    return out;
}

/** Can AMSI give an acceptable scan here, under `policy`? (header). */
inline Availability availability(const Policy& policy = shipped_policy()) {
    Availability a;
    bool readable = false;
    a.providers = registered_providers(readable);
    if (!readable) { a.reason = "The AMSI provider registrations could not be read."; return a; }
    if (a.providers.empty()) { a.reason = "No AMSI provider is registered."; return a; }
    if (a.providers.size() != 1) { a.reason = std::to_string(a.providers.size()) + " AMSI providers are registered; only one can be attributed."; return a; }
    const Identity& id = a.providers.front();
    if (!id.signature_valid) { a.reason = "The AMSI provider " + id.clsid + " is not validly signed."; return a; }
    switch (decide_before_scan(policy, id)) {
        case Verdict::denied: a.reason = "The AMSI provider " + id.clsid + " (" + id.signer + " " + version_text(id.file_version) + ") is denied."; return a;
        case Verdict::unknown: a.reason = "The AMSI provider " + id.clsid + " (" + id.signer + " " + version_text(id.file_version) + ") is not validated for VIRULE."; return a;
        case Verdict::allowed: break;
    }
    a.usable = true;
    return a;
}

/**
 * SCAN ONE FILE through IAntimalware::Scan (header). `am` is the caller's
 * CAntimalware; `id` the one allowed provider; the file is opened for
 * reading with others allowed to read only, so it cannot change while it is
 * served.
 */
inline FileResult scan_file(IAntimalware* am, const Identity& id, const Policy& policy, const fs::path& file) {
    FileResult r;
    r.path = detail::utf8(file.wstring());
    const HANDLE h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) { r.hr = HRESULT_FROM_WIN32(GetLastError()); r.outcome = FileOutcome::incomplete; return r; }
    LARGE_INTEGER size{};
    FILETIME before{}, after{};
    GetFileSizeEx(h, &size);
    GetFileTime(h, nullptr, nullptr, &before);
    r.size = static_cast<std::uint64_t>(size.QuadPart);
    Coverage cov;
    auto* stream = new detail::Stream(h, r.size, file.wstring(), &cov);
    AMSI_RESULT result = AMSI_RESULT_DETECTED;   // never starts clean
    IAntimalwareProvider* provider = nullptr;
    const HRESULT hr = am->Scan(stream, &result, &provider);
    stream->Release();
    LARGE_INTEGER size_after{};
    const bool unchanged = GetFileSizeEx(h, &size_after) && size_after.QuadPart == size.QuadPart &&
                           GetFileTime(h, nullptr, nullptr, &after) && CompareFileTime(&before, &after) == 0;
    CloseHandle(h);
    if (provider) {
        LPWSTR name = nullptr;
        if (SUCCEEDED(provider->DisplayName(&name)) && name) { r.provider = detail::utf8(name); CoTaskMemFree(name); }
        provider->Release();
    }
    Identity named = id;
    named.display_name = r.provider;
    const bool matches = !r.provider.empty() && decide(policy, named) == Verdict::allowed && detail::loaded_is(detail::wide(id.dll));
    r.hr = static_cast<long>(hr);
    r.result = SUCCEEDED(hr) ? static_cast<unsigned long>(result) : 0;
    r.covered = cov.covered();
    r.outcome = classify(static_cast<long>(hr), r.result, matches, cov.complete(r.size), unchanged);
    return r;
}

/** The qualification harness's in-memory content (EICAR assembled at run
 *  time), through the same stream class and the same Scan call. */
inline FileResult scan_memory(IAntimalware* am, const Identity& id, const Policy& policy, const std::string& bytes, const std::wstring& name) {
    FileResult r;
    r.path = detail::utf8(name);
    r.size = bytes.size();
    Coverage cov;
    auto* stream = new detail::Stream(&bytes, name, &cov);
    AMSI_RESULT result = AMSI_RESULT_DETECTED;
    IAntimalwareProvider* provider = nullptr;
    const HRESULT hr = am->Scan(stream, &result, &provider);
    stream->Release();
    if (provider) {
        LPWSTR n = nullptr;
        if (SUCCEEDED(provider->DisplayName(&n)) && n) { r.provider = detail::utf8(n); CoTaskMemFree(n); }
        provider->Release();
    }
    Identity named = id;
    named.display_name = r.provider;
    const bool matches = !r.provider.empty() && decide(policy, named) == Verdict::allowed;
    r.hr = static_cast<long>(hr);
    r.result = SUCCEEDED(hr) ? static_cast<unsigned long>(result) : 0;
    r.covered = cov.covered();
    r.outcome = classify(static_cast<long>(hr), r.result, matches, cov.complete(r.size), true);
    return r;
}

/** The whole set's answer (header). */
struct SetResult {
    bool ran = false;                 // the configuration was usable and every file was presented
    FileOutcome outcome = FileOutcome::incomplete;
    Identity provider;
    std::vector<FileResult> files;    // every file not clean (all of them when few)
    std::uint64_t file_count = 0;
    std::string reason;
};

/**
 * SCAN EVERY REGULAR FILE under the targets (a target may be a file) with
 * the one allowed provider (header). Links are never followed; a folder that
 * cannot be walked whole is incomplete. `keep_going` false stops: what was
 * not presented is not scanned, so the set is incomplete.
 */
inline SetResult scan_targets(const std::vector<fs::path>& targets, const std::function<bool()>& keep_going,
                              const std::function<void()>& heartbeat, const Policy& policy = shipped_policy()) {
    SetResult s;
    const Availability a = availability(policy);
    if (!a.usable) { s.reason = a.reason; if (!a.providers.empty()) s.provider = a.providers.front(); return s; }
    s.provider = a.providers.front();
    detail::Com com;
    IAntimalware* am = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(CAntimalware), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&am))) || !am) {
        s.reason = "The Antimalware Scan Interface is not available.";
        return s;
    }
    std::vector<fs::path> files;
    bool walked = true;
    std::error_code ec;
    for (const auto& t : targets) {
        if (fs::is_regular_file(fs::symlink_status(t, ec))) { files.push_back(t); continue; }
        if (!fs::is_directory(t, ec)) { walked = false; break; }
        for (auto it = fs::recursive_directory_iterator(t, fs::directory_options::none, ec);
             !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            // An entry whose status cannot be read is never skipped: the
            // walk is incomplete, so the set is never clean.
            std::error_code fec;
            const bool link = it->is_symlink(fec);
            if (fec) { walked = false; break; }
            if (link) { if (it->is_directory(fec)) it.disable_recursion_pending(); continue; }
            const bool regular = it->is_regular_file(fec);
            if (fec) { walked = false; break; }
            if (regular) files.push_back(it->path());
        }
        if (ec) { walked = false; break; }
    }
    bool any_detected = false, any_not_clean = false, any_incomplete = !walked, stopped = false;
    for (const auto& f : files) {
        if (keep_going && !keep_going()) { stopped = true; break; }
        if (heartbeat) heartbeat();
        FileResult r = scan_file(am, s.provider, policy, f);
        ++s.file_count;
        if (s.provider.display_name.empty() && !r.provider.empty()) s.provider.display_name = r.provider;
        if (r.outcome == FileOutcome::detected) any_detected = true;
        else if (r.outcome == FileOutcome::not_clean) any_not_clean = true;
        else if (r.outcome == FileOutcome::incomplete) any_incomplete = true;
        if (r.outcome != FileOutcome::clean || s.files.size() < 50) s.files.push_back(std::move(r));
    }
    am->Release();
    s.ran = !stopped;
    if (any_detected) s.outcome = FileOutcome::detected;
    else if (any_not_clean) s.outcome = FileOutcome::not_clean;
    else if (any_incomplete || stopped) s.outcome = FileOutcome::incomplete;
    else s.outcome = FileOutcome::clean;
    if (stopped) s.reason = "Stopped.";
    else if (!walked) s.reason = "The content to scan could not be read whole.";
    return s;
}
#endif

} // namespace virule::core::amsi_scan
