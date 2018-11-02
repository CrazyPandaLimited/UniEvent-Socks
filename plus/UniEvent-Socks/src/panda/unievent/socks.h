#pragma once
#include "socks/Socks.h"
#include <panda/string_view.h>
#include <panda/unievent/TCP.h>

namespace panda { namespace unievent { namespace socks {

void use_socks (const TCPSP& handle, std::string_view host, uint16_t port = 1080, std::string_view login = "", std::string_view passw = "", bool socks_resolve = true);
void use_socks (const TCPSP& handle, const SocksSP& socks);

}}}
