# email

Fastmail JMAP transactional email for Go services: session discovery, estate
identity selection, send, and sender-side delivery proof.

```sh
go get github.com/growth-labs/packages-go/email
```

## Use it for

- One-off transactional mail from a Go service: alerts, invitations, receipts,
  reports.
- Proving afterwards that a specific message reached the account's Sent
  mailbox (`VerifyDelivered`, `FindSentByMessageID`).

## Do not use it for

- Bulk or campaign sending, list management, or unsubscribe handling.
- Workers-runtime (TypeScript) services: those use `@growth-labs/email` and
  `@growth-labs/mailer`.
- Inbound mail, mailbox sync, or anything that needs JMAP beyond composing and
  submitting one message.

## Shape

```go
token, err := email.LoadTokenFile("/etc/foundry/secrets/fastmail.token")
client, err := email.New(token, &http.Client{Timeout: 30 * time.Second})
messageID, err := client.Send(ctx, []string{"someone@fulcrum-labs.com"}, subject, body)
delivered, err := client.VerifyDelivered(ctx, messageID, 2*time.Minute)
```

`example_test.go` is the complete worked example.

## What it guarantees

- **The estate identity, never the operator's.** The Fastmail account behind
  the shared token also holds a personal identity. `Send` resolves the
  `@fulcrum-labs.com` identity and fails loudly if the account has none; it
  never falls back to "the first identity".
- **Retry safety is evidence-based.** `IsUnsubmitted(err)` is true only when
  the transport proves no message was submitted. A lost response is
  deliberately *not* marked: it may already have been delivered, so retrying
  it automatically would double-send. Permanent validation errors can also
  be unsubmitted; retrying them unchanged will not help.
- **Rate limits have typed evidence.** A bounded retry policy can require
  `email.IsUnsubmitted(err) && email.IsRateLimited(err)`. Use `errors.As` with
  `*email.RateLimitError` for `StatusCode`, `Method`, and the `RetryAfter`
  duration (HTTP seconds/date, capped at 24 hours; zero means absent, invalid,
  or elapsed). No provider description is included in the rate-limit error.
  HTTP 429 rejects the whole request; a JMAP `rateLimit` rejection must also
  leave the actual submission proven unsubmitted. A draft rejection alone
  cannot override a missing, partial, or contradictory submission result.
- **The token file is a guard.** `LoadTokenFile` requires a regular
  mode-0600 file holding exactly one line.
- **Message-ID is caller-owned.** `Send` mints one so the caller can prove
  delivery later; `SendWithMessageID` keeps one stable across durable
  attempts. Header injection through it is rejected.

Every one of those guards is proven falsifiable in `guards_test.go`.
Rate-limit classification and ambiguous submission boundaries are exercised
through the real client against a synthetic JMAP server in `client_test.go`.
Protocol basis: [RFC 8620 errors and SetError](https://www.rfc-editor.org/rfc/rfc8620.html#section-3.6),
[HTTP 429](https://www.rfc-editor.org/rfc/rfc6585.html#section-4), and
[Fastmail's JMAP support](https://www.fastmail.com/dev/).

## Configuration

| Value | Where it lives |
| --- | --- |
| JMAP bearer token | mode-0600 file on the host; the value's home is Vaultwarden (`fastmail-api-token`) |
| Sending identity | resolved from the account: the `@fulcrum-labs.com` identity |
| Recipients | the caller's own configuration; this package holds no lists |

No value is ever compiled in, and this package holds no durable state: budget
accounting and retry policy belong to the caller, which has the database
connection this package deliberately does not.
