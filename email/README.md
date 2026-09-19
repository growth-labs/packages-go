# email

Cloudflare Email Sending transactional mail for Go services: builds a
minimal RFC 5322 message and posts it to Cloudflare's `send_raw` REST
endpoint.

```sh
go get github.com/growth-labs/packages-go/email
```

## Use it for

- One-off transactional mail from a Go service: alerts, invitations, receipts,
  reports.

## Do not use it for

- Bulk or campaign sending, list management, or unsubscribe handling.
- Workers-runtime (TypeScript) services: those use `@growth-labs/email` and
  `@growth-labs/mailer`.
- Sending as a specific person's own mailbox. This client always sends as
  one configured sender address; if a consumer ever needs that, it needs a
  different transport, not this one (see "What this does not do" below).

## Shape

```go
token, err := email.LoadTokenFile("/etc/myservice/secrets/cloudflare-email.token")
client, err := email.New(email.Config{
	AccountID: "<your Cloudflare account id>", // not secret
	APIToken:  token,
	From:      "alerts@example.org",
}, &http.Client{Timeout: 30 * time.Second})
messageID, err := client.Send(ctx, []string{"someone@example.net"}, subject, body)
```

`example_test.go` is the complete worked example.

## What it guarantees

- **Loud failure, not a silent no-op.** `New` validates the account id, API
  token, and from address up front, so a misconfiguration is a boot-time
  error. A provider-reported rejection (Cloudflare `success: false`, or any
  non-2xx response) is always surfaced as an error carrying the provider's
  own code and message -- never swallowed into an apparent success.
- **Retry safety is evidence-based.** `IsUnsubmitted(err)` is true only when
  the transport proves no message was submitted: a dial/DNS failure before
  any bytes went out, a rate limit, or a provider-reported rejection (a real
  HTTP response is always Cloudflare's own verdict, proven either way, never
  ambiguous). A genuine network error while a request was already in flight
  (for example a timeout mid-response) is deliberately *not* marked: the
  message may already have been accepted, so retrying it automatically could
  double-send.
- **Rate limits have typed evidence.** Use `errors.As` with
  `*email.RateLimitError` for `StatusCode` and the `RetryAfter` duration
  (HTTP seconds/date, capped at 24 hours; zero means absent, invalid, or
  elapsed).
- **The token file is a guard.** `LoadTokenFile` requires a regular
  mode-0600 file holding exactly one line.
- **Message-ID is caller-owned.** `Send` mints one under the from address's
  own domain so a caller can log it for correlation; `SendWithMessageID`
  keeps one stable across durable attempts. Header injection through the
  Message-ID, subject, or any recipient is rejected.

## What this does not do

Cloudflare's `send_raw` call is synchronous: its response is the only
delivery evidence there ever is. Unlike a JMAP-based transport, there is no
account-side mailbox to poll afterward, so this package has no
`VerifyDelivered` or `FindSentByMessageID` equivalent -- a caller that
needs delivery reconciliation for an ambiguous outcome must treat it as
withheld and surface it loudly, not poll for eventual proof. Cloudflare may
also rewrite the raw MIME `Message-ID` header it actually relays, so
downstream reconciliation by exact Message-ID alone is not reliable
end-to-end evidence (KB `cloudflare-email-sending-may-rewrite-message-id`).

Every guard above is proven falsifiable in `guards_test.go`. The real
client's request/response handling is exercised against a fake Cloudflare
API in `client_test.go`.

## Configuration

| Value | Where it lives |
| --- | --- |
| Cloudflare API token (Email Sending scope) | mode-0600 file on the host; the value's home is your own secret store |
| Cloudflare account id | not secret; your deployment's own Cloudflare account id |
| From address | not secret; must be on a domain already onboarded to Cloudflare Email Sending on that account -- a domain that only has Cloudflare Email *Routing* (inbound) enabled is a different product and is not onboarded for sending |
| Recipients | the caller's own configuration; this package holds no lists |

No value is ever compiled in, and this package holds no durable state:
budget accounting and retry policy belong to the caller, which has the
database connection this package deliberately does not.
