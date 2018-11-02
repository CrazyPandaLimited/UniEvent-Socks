#pragma once
#include <cstdint>
#include "Socks.h"
#include <panda/unievent/TCP.h>

namespace panda { namespace unievent { namespace socks {

using panda::net::SockAddr;

struct SocksFilter;
using SocksFilterSP = iptr<SocksFilter>;

struct SocksFilter : StreamFilter, lib::AllocatedObject<SocksFilter, true> {
    enum class State {
        initial          = 1,
        connecting_proxy = 2,
        resolving_host   = 3, // cancelable async resolve
        handshake_write  = 4, // handshaking, not cancelable
        handshake_reply  = 5, // waiting for reply, not cancelable
        auth_write       = 6,
        auth_reply       = 7,
        connect_write    = 8,
        connect_reply    = 9,
        connected        = 10, // success
        parsing          = 11, // something not parsed yet
        eof              = 12,
        canceled         = 13, // timeout happened
        error            = 14,
        terminal         = 15
    };
    static constexpr double PRIORITY = 100;
    static const     void*  TYPE;

    virtual ~SocksFilter();
    SocksFilter (Stream* stream, SocksSP socks);
    
    StreamFilterSP clone() const override { return StreamFilterSP(new SocksFilter(handle, socks_)); };

private:
    void do_handshake();
    void do_auth();
    void do_resolve();
    void do_connect();
    void do_connected();
    void do_eof();
    void do_error(const CodeError* err = CodeError(ERRNO_SOCKS));

    void on_connection(StreamSP, const CodeError* err) override;
    void write(WriteRequest* write_request) override;
    void connect(ConnectRequest* connect_request) override;
    void on_connect(const CodeError* err, ConnectRequest* connect_request) override;
    void on_write(const CodeError* err, WriteRequest* write_request) override;
    void on_read(string& buf, const CodeError* err) override;
    void on_shutdown(const CodeError* err, ShutdownRequest* shutdown_request) override;
    void on_eof() override;
    void on_reinit() override;

    bool is_secure() override { return true; }

    void  state(State s) { state_ = s; }
    State state() const { return state_; }

    void init_parser();

private:
    SocksSP  socks_;
    State    state_;
    string   host_;
    uint16_t port_;
    addrinfo hints_;
    SockAddr sa_;

    TCPConnectRequest*      connect_request_;
    iptr<TCPConnectRequest> socks_connect_request_;
    iptr<ResolveRequest>    resolve_request_;

    // parser state
    int cs;

    bool    noauth;
    uint8_t auth_status;
    uint8_t atyp;
    uint8_t rep;
};

struct SocksHandshakeRequest : WriteRequest {
    ~SocksHandshakeRequest() {}

    SocksHandshakeRequest(write_fn callback, const SocksSP& socks) : WriteRequest(callback) {
        if (socks->loginpassw()) {
            bufs.push_back("\x05\x02\x00\x02");
        } else {
            bufs.push_back("\x05\x01\x00");
        }
    }
};

struct SocksAuthRequest : WriteRequest {
    ~SocksAuthRequest() {}

    SocksAuthRequest(write_fn callback, const SocksSP& socks) : WriteRequest(callback) {
        bufs.push_back(string("\x01") + (char)socks->login.length() + socks->login + (char)socks->passw.length() + socks->passw);
    }
};

struct SocksCommandConnectRequest : public WriteRequest {
    ~SocksCommandConnectRequest() {}

    SocksCommandConnectRequest(write_fn callback, const string& host, uint16_t port) : WriteRequest(callback) {
        _EDEBUGTHIS("connecting to: %.*s:%d", (int)host.length(), host.data(), port);
        uint16_t nport = htons(port);
        bufs.push_back(string("\x05\x01\x00\x03") + (char)host.length() + host + string((char*)&nport, 2));
    }

    SocksCommandConnectRequest(write_fn callback, const SockAddr& sa) : WriteRequest(callback) {
        _EDEBUGTHIS("ctor");
        if (sa.is_inet4()) {
            auto& sa4 = sa.inet4();
            bufs.push_back(string("\x05\x01\x00\x01") + string_view((char*)&sa4.addr(), 4) + string_view((char*)&sa4.get()->sin_port, 2));
        } else if (sa.is_inet6()) {
            auto& sa6 = sa.inet6();
            bufs.push_back(string("\x05\x01\x00\x04") + string((char*)&sa6.addr(), 16) + string((char*)&sa6.get()->sin6_port, 2));
        } else {
            throw Error("Unknown address family");
        }
    }
};

}}} // namespace panda::event::socks