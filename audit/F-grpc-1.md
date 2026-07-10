# F-grpc-1: gRPC Handshake server bound to all interfaces despite documented "localhost"
- Severity: medium
- Status: Verified-Fixed
- Area: grpc

## Summary
`spring.grpc.server.address` was unset, so Spring gRPC resolved the wildcard sentinel (`*`) and bound
the plaintext, unauthenticated `Handshake.Negotiate` RPC on `:9090` to all interfaces (0.0.0.0/::).
The code/proto/CLAUDE.md all describe this as "PLAINTEXT localhost", so the actual bind contradicted
the stated threat model.

## Impact
An operator trusting the "localhost" wording would not firewall port 9090 and would in fact expose an
unauthenticated plaintext RPC to the LAN/compose network. Blast radius is low (the RPC is a pure,
stateless function echoing only already-public version/name data), but the intent/behaviour gap is a
real config bug and a defense-in-depth loss ahead of Session Four's mTLS.

## Remediation
Set `spring.grpc.server.address=127.0.0.1` in `application.properties` so the documented assumption is
enforced. The smoke connects to `127.0.0.1:9090`, so reachability is preserved. Re-evaluate the bind
address deliberately when Session Four introduces mTLS.

## Evidence
- `src/main/resources/application.properties`: `spring.grpc.server.address=127.0.0.1` added.
- Confirmed by decompiling `spring-boot-grpc-server-4.1.0` (`NettyAddress.fromProperties` → wildcard
  when `address` is null).
