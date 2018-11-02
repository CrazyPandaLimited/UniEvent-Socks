#pragma once
#include <cstdint>
#include <panda/string.h>
#include <panda/uri/socks.h>
#include <panda/unievent/Error.h>

namespace panda { namespace unievent { namespace socks {

struct Socks : virtual Refcnt {
    using URI = panda::uri::URI;

    Socks (const string& host, uint16_t port, const string& login = "", const string& passw = "", bool socks_resolve = true)
            : host(host), port(port), login(login), passw(passw), socks_resolve(socks_resolve) {}

    Socks (const string& uri, bool socks_resolve = true) : Socks(URI::socks(uri), socks_resolve) {}

    Socks (const URI::socks& uri, bool socks_resolve = true) : socks_resolve(socks_resolve) {
        if (uri.host()) {
            host  = uri.host();
            port  = uri.port();
            login = uri.user();
            passw = uri.password();
        }

        if (login.length() > 0xFF) throw Error("Bad login length");
        if (passw.length() > 0xFF) throw Error("Bad password length");
    }

    bool configured () const { return !host.empty(); }
    bool loginpassw () const { return !login.empty(); }

    string   host;
    uint16_t port;
    string   login;
    string   passw;
    bool     socks_resolve;
};

using SocksSP = iptr<Socks>;

}}}
