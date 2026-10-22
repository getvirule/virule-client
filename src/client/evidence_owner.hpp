#pragma once
// WHOSE EVALUATION EVIDENCE IT IS (2026-10-22; docs/ARCHITECTURE.md
// "Evaluation evidence delivery", "Whose evidence it is").
//
// THE QA-LAPTOP ROOT CAUSE: with a developer account signed in on a shared
// computer, the evaluator's packages were sent under that account, refused
// ("Not authorized.") and climbed the retry ladder to 30 minutes. A package
// (and a request) is now delivered only under its evaluator's account and
// otherwise WAITS (shared/evidence_queue.hpp Owner).
//
// THE CLIENT HOLDS NO ACCOUNT ID: /v1/account/me names email, display name,
// capabilities and an opaque `account_hint`, never the id, and the
// package's `evaluator_id` IS the evaluator's account id
// (v2_mvp docs/EVALUATION_VIRULE.md section 2). So the decision is made from
// what this computer and the service already state, in this order:
//
//   1. nobody signed in                         -> SignedOut
//   2. the signed-in account's id known here:   == evaluator -> Mine, else OtherAccount.
//      Known from this account's own install jobs (transfers\, account_email
//      = the signed-in email): each one's ticket.json carries the
//      evaluator_id the service signed for this account; or learned by (3).
//   3. else one read of the assignment's ticket under this account
//      (GET /v1/assignments/<id>/ticket; the service answers ONLY the
//      caller's own assignment and writes nothing):
//        200 -> Mine (and the account's id is learned: the ticket's evaluator_id)
//        409 -> Mine (the caller's own assignment, not active: the service decides)
//        404 -> OtherAccount, remembered for this sign-in
//        403 -> OtherAccount (the account lacks the evaluator capability),
//               never remembered: a capability can change, so asked again later
//        401, 5xx, no answer -> Unknown (the attempt goes; the service decides)
//
// `security\evaluator.cred` is never used for this: it is one file per
// computer, overwritten by whichever account last made a launch chain, and
// it survives another account's sign-out.
//
// Every sign-in and sign-out moves the generation (account.hpp
// g_on_account_changed -> note_account_changed), which forgets everything
// learned for the previous sign-in.

#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>

#include "client/transfers.hpp"
#include "shared/evidence_queue.hpp"
#include "virule/core/evaluation_distribution.hpp"
#include "virule/core/evaluation_evidence.hpp"

namespace vclient::evidence_owner {

namespace fs = std::filesystem;
namespace ed = virule::core::evaluation_distribution;
namespace ee = virule::core::evaluation_evidence;
using evidence::Owner;

inline std::atomic<std::uint64_t>& account_generation() { static std::atomic<std::uint64_t> g{ 0 }; return g; }
inline void note_account_changed() { account_generation().fetch_add(1); }

inline std::string ticket_evaluator(const fs::path& root, const std::string& assignment_id) {
    if (!ee::is_hex32(assignment_id)) return {};
    return ee::json::opt_string(ee::read_document(root / L"evaluator" / L"assignments" / fs::path(assignment_id) / L"ticket.json"), "evaluator_id");
}

// The signed-in account's id as this computer knows it: the evaluator_id
// of a ticket written for one of this account's own install jobs.
inline std::string local_account_id(const fs::path& root, const std::string& email) {
    if (email.empty()) return {};
    for (const auto& j : ed::list_jobs(root)) {
        if (!ed::is_install(j) || j.account_email != email) continue;
        const std::string id = ticket_evaluator(root, j.assignment_id);
        if (!id.empty()) return id;
    }
    return {};
}

class Resolver {
public:
    Resolver(fs::path root, transfers::Service* service) : root_(std::move(root)), service_(service) {}

    Owner owner(const std::string& assignment_id, const std::string& evaluator_id) {
        std::string email;
        if (!service_ || !service_->signed_in(email) || email.empty()) return Owner::SignedOut;
        const std::string evaluator = evaluator_id.empty() ? ticket_evaluator(root_, assignment_id) : evaluator_id;
        {
            std::lock_guard<std::mutex> lock(m_);
            sync_locked(email);
            if (account_id_.empty()) account_id_ = local_account_id(root_, email);
            if (!account_id_.empty() && !evaluator.empty()) return account_id_ == evaluator ? Owner::Mine : Owner::OtherAccount;
            const auto hit = known_.find(assignment_id);
            if (hit != known_.end()) return hit->second;
        }
        if (!ee::is_hex32(assignment_id)) return Owner::Unknown;
        // The network read happens outside the lock (it takes the account's
        // own locks for its authorization).
        const transfers::Reply r = service_->call("GET", "/v1/assignments/" + assignment_id + "/ticket", "", "", {});
        std::lock_guard<std::mutex> lock(m_);
        if (!sync_locked(email)) return Owner::Unknown;   // the account changed meanwhile
        if (r.status == 200) {
            std::string_view ticket;
            std::string tev;
            if (ee::json::member(r.body, "ticket", ticket)) tev = ee::json::opt_string(ticket, "evaluator_id");
            if (!tev.empty()) account_id_ = tev;
            const Owner o = (evaluator.empty() || tev.empty() || tev == evaluator) ? Owner::Mine : Owner::OtherAccount;
            known_[assignment_id] = o;
            return o;
        }
        if (r.status == 409) { known_[assignment_id] = Owner::Mine; return Owner::Mine; }
        if (r.status == 404) { known_[assignment_id] = Owner::OtherAccount; return Owner::OtherAccount; }
        if (r.status == 403) return Owner::OtherAccount;
        return Owner::Unknown;
    }

    evidence::OwnerFn fn() {
        return [this](const std::string& a, const std::string& e) { return owner(a, e); };
    }

private:
    // True when nothing changed since the last look; a new sign-in (another
    // generation, another email) forgets what the previous one learned.
    bool sync_locked(const std::string& email) {
        const std::uint64_t g = account_generation().load();
        if (g == generation_ && email == email_) return true;
        generation_ = g;
        email_ = email;
        account_id_.clear();
        known_.clear();
        return false;
    }

    fs::path root_;
    transfers::Service* service_ = nullptr;
    std::mutex m_;
    std::uint64_t generation_ = ~0ull;
    std::string email_;
    std::string account_id_;
    std::map<std::string, Owner> known_;
};

} // namespace vclient::evidence_owner
