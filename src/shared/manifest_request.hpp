#pragma once
// THE ADMIN MANIFEST REQUEST: the one exchange with the VIRULE update
// service, as a unit that knows nothing about the Admin install around it.
//
// One request per call (two only when a service that predates the check-in
// refuses the POST):
//
//   - when this machine can identify itself (shared/usage_checkin.hpp), a
//     POST that names the installation and carries the Admin's pending
//     usage batches, if any; the answer is the manifest plus the
//     acknowledgement, and exactly the acknowledged batches are deleted;
//   - otherwise, or when the POST was answered with anything but 200, the
//     plain GET this has always been. A POST that got NO answer is not
//     retried as a GET: the network is down either way, and the caller is
//     often a bridge request with its own deadline.
//
// The update check never depends on the batches: any failure on that side
// leaves them on disk and the manifest answer is used exactly as before.

#include <string>

#include "shared/http_client.hpp"
#include "shared/usage_checkin.hpp"

namespace vclient::manifest_request {

struct Result {
    bool answered = false;    // a 200 body is in `body`
    bool reached = false;     // ANY HTTP response arrived (update_health)
    unsigned long status = 0; // of the last request made; 0 = no response
    std::string body;
    size_t delivered = 0;     // batches acknowledged and deleted
    bool seen = false;        // the service put this installation on record
};

inline Result run(const http::Url& u, size_t max_bytes,
                  const usage_checkin::Pending& pending) {
    Result r;
    bool need_get = pending.body.empty();
    if (!need_get) {
        const bool got = http::http_post_json(u.host.c_str(), u.port, u.secure,
            u.path.c_str(), pending.body, max_bytes, r.status, r.body);
        r.reached = r.status != 0;
        if (got && r.status == 200) {
            r.answered = true;
            r.delivered = usage_checkin::apply_ack(r.body, pending);
            r.seen = usage_checkin::seen(r.body);
        } else {
            need_get = r.reached;
        }
    }
    if (need_get) {
        const bool got = http::http_get(u.host.c_str(), u.port, u.secure,
            u.path.c_str(), max_bytes, r.status, r.body);
        r.reached = r.reached || r.status != 0;
        r.answered = got && r.status == 200;
    }
    return r;
}

} // namespace vclient::manifest_request
