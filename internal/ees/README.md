# Embedded EES profile

## Deployment scope

EES currently supports **only the free5GC single-UPF scenario**. Keep it
disabled (`ees.enabled: false`, the default) in ULCL or other multi-UPF
deployments; ULCL support for EES can be addressed separately.

With EES disabled, no EES code runs on the PFCP path: PFCP messages and
forwarder calls are identical to upstream, including for ULCL-style sessions.
`internal/pfcp/ees_disabled_parity_test.go` enforces this against a golden
trace recorded from upstream free5gc/go-upf (`0012ceb`; re-recording on
`6404375` gives the same trace).

This implementation exposes `USER_DATA_USAGE_MEASURES`, `PER_SESSION`, IPv4,
and `VOLUME_MEASUREMENT` / `THROUGHPUT_MEASUREMENT`. Other TS 29.564 values
(`USER_DATA_USAGE_TRENDS`, `PER_APPLICATION`, `PER_FLOW`,
`APPLICATION_RELATED_INFO`) are rejected with 400 as not supported, with an
error distinct from values the specification does not define.
It uses existing SMF-provisioned measurements, not shadow URRs.

## URR selection is intentionally constrained

`SingleUPFMAQEURRID` remains **2**: the free5GC single-UPF MAQE rule
(measurement after QoS enforcement). This is an implementation convention,
not a 3GPP-mandated numeric ID. URR IDs are session-scoped.
See the [free5GC CHF design](https://free5gc.org/doc/Chf/design/).

ULCL, other SMF ID-allocation schemes, and application/flow-specific charging
URRs are outside this profile. Do not sum every URR: measurements can overlap.
The SMF must provision URR 2 and its reporting triggers. If it does not,
subscriptions remain pending without fabricated data.

## API and reporting behavior

- HTTP/1.1 and cleartext HTTP/2 (h2c) are supported.
- `ueIpAddress` is an object, e.g. `{"ipv4Addr":"10.60.0.1"}`.
  Alternatively, `anyUe: true` selects all IPv4 sessions.
- `eventReportingMode.repPeriod` is a positive number of seconds for `PERIODIC`.
  `reportPeriod` is not recognized as the interval.
- Creation returns the same absolute resource URI in `Location` and
  `subscriptionId`; DELETE uses the last path segment as the ID, at the exact
  `/nupf-ee/v1/ee-subscriptions/{id}` route.
- The response URI uses the direct request scheme and authority. Untrusted
  forwarded headers are not used. Reverse proxies with a different external
  scheme/path need an advertised-root design before they can be supported.
- Exactly one event is accepted. Empty measurement lists, unsupported
  measurements, and application/flow filters with `PER_SESSION` are rejected.
- Volume values use TS 29.571 `TrafficVolume` strings, including explicit
  `"0 B"` for a real zero-valued measurement.
- `ONE_TIME` waits for the first real measurement and is deleted only after
  successful delivery. No session or no report is **not** zero usage.
- `PERIODIC` notifications use the subscription's `repPeriod`, rounded up to a
  whole number of URR 2 measurement periods of the reporting session (from its
  CreateURR with the PERIO trigger), e.g. `repPeriod` 25 s over a 10 s URR period
  is sent every 30 s, and 5 s becomes 10 s. A batch is sent as soon as it spans
  that many URR periods, aligned to kernel report arrival. If reports stop
  (e.g. session release), the partial batch is sent half a URR period after the
  deadline. Without a periodic URR 2 the `repPeriod` is used as is. If an `anyUe`
  batch mixes sessions with different URR periods, the longest one is used.
  The UPF config has no global period. No-data intervals do not generate
  synthetic reports.
- One request per subscription may be in flight. Different subscribers run
  independently. Cancellation propagates to HTTP requests, and shutdown waits
  for notification workers. Failed batches are retained and retried with a
  one-second minimum delay; explicit deletion prevents restoration of a batch.
- Accumulation uses local/remote SEIDs, an allocation generation, and UE IP.
  Recycling a local SEID does not merge different session lifetimes.
- PFCP response usage reports reach EES through a separate buffer-only hook,
  never through the PFCP report queue, so they are not reported to the SMF
  again and cannot block the PFCP loop. They are keyed by local SEID; final
  reports retain identity captured before session cleanup. When EES is
  disabled the hook is not registered and this path is skipped entirely.

### Remaining profile limits

Target selection currently uses IPv4, not SUPI/DNN/S-NSSAI. Supplementary
identifiers sent alongside IPv4 by the SMF are not retained as independent
filters in the created resource. Deploy only where the targeted IPv4 uniquely
identifies the intended session scope; overlapping address domains need an
extended identity/filter model. This profile does not implement those selectors,
feature negotiation, expiry/max-report controls, or immediate-report requests.

An HTTP timeout does not prove the consumer failed to process a notification.
Retries retain the existing at-least-once behavior; exactly-once delivery is
not guaranteed.

## Regression tests

From the repository root:

```sh
go test -race ./internal/ees ./internal/pfcp
go test -race -run TestValidation ./pkg/app
go test -short ./...
```

`TestPFCPParityWithEESDisabled` / `TestPFCPParityWithEESEnabled` drive a real
PFCP server loop over UDP through a ULCL-style session (several PDRs/URRs,
not only URR 2, partial UpdatePDRs, branch removal, kernel reports, deletion)
with small, colliding CP/UP SEIDs. Both must reproduce the upstream golden
byte-for-byte; the enabled variant also checks what EES receives. To re-record
the golden, run the disabled test with `PFCP_PARITY_WRITE=1` on an upstream
checkout, never on this branch.

The generated-client contract test has an isolated module so the UPF's runtime
dependencies are not upgraded. It uses the same OpenAPI client revision as the
reviewed SMF implementation, tests h2c create/delete and notification decoding,
and checks the SMF's resource-URI invariants:

```sh
cd tests/contracts/nupf
go test -race ./...
```

The same module provides `cmd/ees-harness`, which serves the real EES handler
(via `Server.Serve`) plus a test-only control endpoint for injecting usage and
inspecting accepted subscriptions. It lets a consumer in another repository,
such as an SMF, run contract tests against this UPF over HTTP, since Go's
internal-package rule prevents importing the handler directly.
