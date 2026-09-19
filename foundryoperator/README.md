# foundryoperator

Dependency-free signer for FOUNDRY-OPERATOR-V1 operator proofs: the
canonical-JSON, Ed25519-signed request envelope foundryd's operator-proof
surface requires from every non-bearer caller — the operator Unix domain
socket, and the public `/mcp/token` and `/kb/context` routes on
`foundry.fulcrum-labs.com`.

```sh
go get github.com/growth-labs/packages-go/foundryoperator
```

## Use it for

- Any Go service that needs to sign a request foundryd's operator-proof
  verifier (`onlinewire.OperatorProofValue`, `canonicaljson.Canonicalize`)
  checks — over the operator UDS, or over HTTPS to a public operator route.
- A second, independent Go caller of this protocol, so the canonical
  encoding and signing steps exist once, not once per consumer.

```go
proof, signature, err := foundryoperator.Sign(
    principalKey, principalKID, "POST", "/mcp/token", "", body, time.Now(), nil,
)
req.Header.Set("X-Foundry-Operator-Proof", proof)
req.Header.Set("X-Foundry-Operator-Signature", signature)
```

## Do not use it for

- Verifying a proof: this package is a signer only. foundryd's own
  verifier is the one place that logic lives.
- Human/session authentication (OpenAuth login, cookies): use this
  repository's `auth` package. This package is service identity only.
- A new signing format: if foundryd's operator-proof shape changes, this
  package changes once and every consumer picks it up; a consumer never
  encodes its own variant.

## Extracted at the second real use

`fulcrum-labs/quarry`'s `adapters/foundry` package carried the first
implementation, duplicated internally between `CapabilityClient.sign` and
`operatorHTTPClient.sign`. `fulcrum-labs/cockpit`'s named-responsibility
knowledge reader (CP-06) is the second real, separately deployed use.
Quarry's two copies are replaced with calls to `Sign`, not left standing
beside it. The wire format is also implemented once more in JavaScript,
in `olympus-control-plane`'s `.claude/hooks/shared/kb-transport.mjs`
(`mintFoundryMcpToken`, `canonicalizeJson`) — that module documents the
same rule for its language: a signing format implemented more than once
is a defect this package (and that file) exist to prevent, not a pattern
to extend with a third or fourth copy.
