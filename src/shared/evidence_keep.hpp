#pragma once
// WHAT UNINSTALL & DELETE DATA KEEPS (2026-10-22; docs/ARCHITECTURE.md
// "Install / uninstall", "Evaluation evidence delivery").
//
// OWNER RULING 2026-10-22: Delete Data removes everything EXCEPT undelivered
// evaluation evidence and report drafts; delivery resumes after a reinstall
// once the evaluator signs in. THE KEPT SET (PENDING OWNER DECISION) is, for
// every evaluator assignment with UNFINISHED BUSINESS (an outbox or
// .incoming package of it, a pending request in evidence\requests, a
// non-empty evaluator\assignments\<id>\report_draft.json, or an
// open_session.json):
//
//   evidence\outbox\<pkg>\, evidence\.incoming\<pkg>\, evidence\delivery\<pkg>.json
//   evidence\requests\<assignment>.*
//   evidence\progress\<assignment>.json
//   evidence\receipts\<pkg>.json of that assignment's packages
//   evaluator\assignments\<id>\{ledger.json, open_session*.json, report_draft.json, captures\}
//
// (the ledger, the checkpoint and the captures are what the wrapper's
// recovery and the session numbering need). The ticket and security\
// credentials are NOT kept: the service issues them again. Everything else
// under the data root goes, as before; with nothing kept the root itself
// goes, exactly as before.
//
// Pure filesystem over an explicit root, so tests/evidence drives it on a
// temporary tree.

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "virule/core/evaluation_evidence.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace vclient::evidence_keep {

namespace fs = std::filesystem;
namespace ee = virule::core::evaluation_evidence;

inline fs::path assignment_dir(const fs::path& root, const std::string& id) {
    return root / L"evaluator" / L"assignments" / fs::path(id);
}

// Every evaluator assignment with unfinished business, and its packages.
struct Unfinished {
    std::set<std::string> assignments;
    std::set<std::string> outbox, incoming;   // package ids
};

inline void scan_packages(const fs::path& dir, std::set<std::string>& ids, std::set<std::string>& assignments) {
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string id = it->path().filename().string();
        if (!ee::is_hex32(id)) continue;
        ids.insert(id);
        ee::Package p;
        const std::string text = ee::read_document(it->path() / ee::kPackageFileName);
        if (!text.empty() && ee::parse_package(text, p) && ee::is_hex32(p.assignment_id)) assignments.insert(p.assignment_id);
    }
}

inline Unfinished unfinished(const fs::path& root) {
    Unfinished u;
    const ee::Root er = ee::root_under(root);
    scan_packages(ee::outbox_dir(er), u.outbox, u.assignments);
    scan_packages(er.dir / L".incoming", u.incoming, u.assignments);
    std::error_code ec;
    for (fs::directory_iterator it(ee::requests_dir(er), ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.size() > 32 && ee::is_hex32(name.substr(0, 32)) && name[32] == '.') u.assignments.insert(name.substr(0, 32));
    }
    for (fs::directory_iterator it(root / L"evaluator" / L"assignments", ec), end; !ec && it != end; it.increment(ec)) {
        const std::string id = it->path().filename().string();
        if (!ee::is_hex32(id)) continue;
        std::error_code fec;
        const fs::path draft = it->path() / L"report_draft.json";
        const bool draft_held = fs::is_regular_file(draft, fec) && fs::file_size(draft, fec) > 0 &&
                                !ee::read_document(draft).empty();
        if (draft_held || ee::exists_quiet(it->path() / L"open_session.json")) u.assignments.insert(id);
    }
    return u;
}

// The kept paths (files or directories), every one under `root`.
inline std::vector<fs::path> keep_set(const fs::path& root) {
    std::vector<fs::path> keep;
    if (root.empty()) return keep;
    const Unfinished u = unfinished(root);
    if (u.assignments.empty() && u.outbox.empty() && u.incoming.empty()) return keep;
    const ee::Root er = ee::root_under(root);
    const auto add = [&](const fs::path& p) { if (ee::exists_quiet(p)) keep.push_back(p); };
    for (const auto& id : u.outbox) { add(ee::outbox_dir(er, id)); add(er.dir / L"delivery" / fs::path(id + ".json")); }
    for (const auto& id : u.incoming) { add(ee::incoming_dir(er, id)); add(er.dir / L"delivery" / fs::path(id + ".json")); }
    std::error_code ec;
    for (fs::directory_iterator it(ee::requests_dir(er), ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.size() > 32 && name[32] == '.' && u.assignments.count(name.substr(0, 32))) keep.push_back(it->path());
    }
    for (fs::directory_iterator it(ee::receipts_dir(er), ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.size() != 37 || name.compare(32, 5, ".json") != 0) continue;   // package receipts only
        ee::Receipt rc;
        if (ee::read_receipt(er, name.substr(0, 32), rc) && u.assignments.count(rc.assignment_id)) keep.push_back(it->path());
    }
    for (const auto& a : u.assignments) {
        add(ee::progress_path(er, a));
        const fs::path dir = assignment_dir(root, a);
        add(dir / L"ledger.json");
        add(dir / L"report_draft.json");
        add(dir / L"captures");
        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
            const std::wstring name = it->path().filename().wstring();
            if (name.rfind(L"open_session", 0) == 0 && name.size() >= 5 && name.substr(name.size() - 5) == L".json") {
                keep.push_back(it->path());
            }
        }
    }
    std::sort(keep.begin(), keep.end());
    keep.erase(std::unique(keep.begin(), keep.end()), keep.end());
    return keep;
}

inline std::wstring key_of(const fs::path& p) {
    std::wstring w = p.lexically_normal().wstring();
    for (auto& c : w) { if (c == L'/') c = L'\\'; c = (wchar_t)std::towlower(c); }
    while (!w.empty() && w.back() == L'\\') w.pop_back();
    return w;
}

// Is `p` kept, or an ancestor of something kept?
inline int relation(const fs::path& p, const std::vector<std::wstring>& kept) {
    const std::wstring k = key_of(p);
    for (const auto& x : kept) {
        if (x == k) return 2;                                   // kept itself
        if (x.size() > k.size() && x.compare(0, k.size(), k) == 0 && x[k.size()] == L'\\') return 1;   // holds kept
    }
    return 0;
}

inline bool remove_with_retries(const fs::path& p, int attempts = 20) {
    for (int i = 0; i < attempts; ++i) {
        std::error_code ec;
        fs::remove_all(p, ec);
        ec.clear();
        if (!fs::exists(p, ec)) return true;
        Sleep(250);
    }
    std::error_code ec;
    return !fs::exists(p, ec);
}

inline bool remove_except(const fs::path& dir, const std::vector<std::wstring>& kept) {
    bool ok = true;
    std::vector<fs::path> entries;
    std::error_code ec;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) entries.push_back(it->path());
    for (const auto& e : entries) {
        const int r = relation(e, kept);
        if (r == 2) continue;
        if (r == 1) { ok = remove_except(e, kept) && ok; continue; }
        ok = remove_with_retries(e) && ok;
    }
    return ok;
}

// THE DELETE DATA REMOVAL: everything under `root` but `keep`. With nothing
// kept, the root itself goes (as before 2026-10-22). True = nothing outside
// the kept set is left.
inline bool remove_root_keeping(const fs::path& root, const std::vector<fs::path>& keep) {
    if (root.empty()) return true;
    if (keep.empty()) return remove_with_retries(root);
    std::vector<std::wstring> kept;
    for (const auto& k : keep) kept.push_back(key_of(k));
    return remove_except(root, kept);
}

} // namespace vclient::evidence_keep
