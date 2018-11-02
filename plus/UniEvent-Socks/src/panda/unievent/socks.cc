#include "socks.h"
#include "socks/SocksFilter.h"

namespace panda { namespace unievent { namespace socks {

void use_socks (const TCPSP& handle, std::string_view host, uint16_t port, std::string_view login, std::string_view passw, bool socks_resolve) {
    use_socks(handle, new Socks(string(host), port, string(login), string(passw), socks_resolve));
}

void use_socks (const TCPSP& handle, const SocksSP& socks) {
    handle->add_filter(new socks::SocksFilter(handle, socks));
}


}}}
