// Package sideband is the code name for the non-HTTP intercept path.
//
// HTTP stays on the existing proxy. Sideband terminates the other session
// types, opens a new session to the origin, and writes every packet to a
// binary log and a JSON log. The client has to trust this process: TLS,
// DTLS, and QUIC are signed by the proxy CA, and WireGuard only decrypts
// when the operator has installed this process's peer keys.
package sideband
