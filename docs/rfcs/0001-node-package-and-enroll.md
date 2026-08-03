# RFC-C: review-protocol — `node.package` delivery and `node.enroll` registration

Status: draft. This is an **`aicers/review-protocol`** in-repo RFC (the
crate moved from `petabi` to `aicers`; there is no external gate). It is
the ecosystem set's **RFC-C**, referenced by that label from RFC-A/B/D/E;
its filing home is `aicers/review-protocol` (`docs/rfcs/`, its first RFC).
All current-state claims below are verified against `aicers/review-protocol`
`origin/main` @ `bee34d6` — the base these changes land on. This is **post-tag
`main`**, 14 commits **after** the `0.19.0` tag (which points at `257921f8`),
even though the crate version string is still `0.19.0` (not yet bumped). Several
cited facts exist **only on post-tag `main`, not at the tag** — `unary_request`
is `pub(crate)` (removed from the public API), the handshake / `AgentInfo`
fields were renamed to `agent_*`, and `DeleteCustomerData` = 22 — so an
implementer must check out `origin/main` @ `bee34d6`, **not** the `0.19.0` tag,
or they would see a different API surface. Re-verify against `origin/main`
before relying.

Part of the ecosystem install/update path (bootler RFC 0002 §2, §4).
Consumers: `aicers/roxyd` (agent/client side) and `aicers/review`
(manager/server side). Package format and signature come from
bootler RFC 0004 §4–§5.

This document is **self-contained**: it restates inline every cross-repo
contract an issue needs, because AgentCoop issues take their text as sole
input. **The many `RFC-A`/`RFC-B`/`RFC-D2`/`RFC-F` citations below are
provenance, not lookups** — each names where a decision was made, next to a
sentence that already states it. Implementing this crate requires no other
repo's RFC: every wire type it defines (`ServiceSpec`, `DeliveryMode`,
`BootstrapMaterial`, the request/response families, the `AgentInfo` tail) is
spelled out here, and the behaviour attributed to the agent (RFC-B) or the
manager (RFC-D2) is counterparty context, not work this crate does.

**One deliberate exception:** the **identity derivation** — how
`(service_name, host, instance)` becomes bootroot's namespace key, and how
instance numbers are scoped — is single-sourced in **RFC-A §4** and is
intentionally *not* restated here or anywhere else (two subtly different
implementations would fail every `Register` in the fleet, and only after
deployment). This crate carries the parts, not the composed name, so it
performs no derivation of its own; any issue that does must inline
RFC-A §4's rule rather than paraphrase it.

## 1. Summary

review-protocol today can control a service's lifecycle and read its
version, but it has **no way to deliver a software package to a host or
to enroll a new service identity at runtime**. This RFC adds two
Manager→Agent request families, additively:

1. **`node.package`** (proposed code 109) — deliver/install, remove,
   list, and status a module package on the agent's host. Install
   streams the package bytes over the request's QUIC bi-stream.
2. **`node.enroll`** (proposed code 110) — ask the registrar agent (the
   bootroot-co-located roxyd) to mint a new service's bootroot
   enrollment material, for per-service install and host onboarding.

Both are additive: existing `node.*` codes 100–108 are untouched, and an
agent that does not implement the new codes already falls through to the
"unknown request code" arm.

## 2. Current state (verified against `origin/main` @ `bee34d6`, post-tag)

- **Framing.** The public message API is `frame::recv_msg` (`src/frame.rs:12`)
  / `frame::send_msg` (`:25`) over `quinn::RecvStream`/`SendStream`.
  Request/response is assembled internally via a
  now-crate-private `unary_request` (`src/lib.rs:183`, `pub(crate)` since
  the `Remove unary_request from public API` commit) — so a new node
  handler works with `frame::*` and the raw streams directly, not a
  public request helper.
- **Node dispatch.** `handle_node<H: NodeHandler>(…)` (`src/request.rs:617`)
  reads a `code` + `body` and matches `RequestCode`; each arm does
  `parse_args::<NodeXRequest>(body)` → `handler.node_x(req).await` →
  `send_response(send, …)`. The default arm sends
  `"unknown request code: {code}"`. So node requests are unary today.
- **Node codes in use:** the `RequestCode` enum defines `NodeService=100`
  … `NodeVersion=108` (`src/client.rs:94-118`). Codes **109–110 are
  free.** The enum grows additively — `DeleteCustomerData=22`
  (`src/client.rs:83`) is a recently-added code — so new node codes are
  the normal, backward-compatible pattern. (The round-trip tests
  `node_request_code_mapping` and `request_code_serde`,
  `src/request.rs:1069` and `:1056`, pin these numeric mappings and confirm
  109–110 are unused.)
- **A streaming precedent already exists.** `server/stream.rs::process_event_stream<H>(recv:
  RecvStream, handler)` (`src/server/stream.rs:36`) reads a protocol
  header via `recv.read_exact(...)` and then consumes a stream of
  messages off the raw `RecvStream`. So the protocol already has a
  pattern for "take the raw QUIC stream and read a bulk stream over it,"
  which `node.package` install builds on rather than sending one giant
  message.
- **ServiceId families** (`src/service_id.rs`): `node.hostname`,
  `node.logging`, `node.network_interface`, `node.observation`(+
  `.process_list`), `node.power`(+`.reboot`), `node.remote_access`,
  `node.service`, `node.time_sync`, `node.version`. **No `node.package`
  or `node.enroll`.**
- **Version negotiation.** Agent advertises a wire protocol version at
  handshake; the manager enforces a `VersionReq` (server side) — roxyd
  advertises `"0.48.0"`, review requires `>=0.48.0`.

## 3. Gap

- `node.service` is **Start/Stop/Restart/Status by service name** — it
  assumes the unit already exists on the host. It cannot put software
  there.
- `node.version` is **Get / SetOsVersion / SetProductVersion** returning
  strings — version *bookkeeping*, not an install/upgrade actuation.
- Nothing delivers package bytes to a host, and nothing lets the manager
  drive a runtime `bootroot service add` on the registrar agent.

So the manager can restart and record versions, but it cannot **install
or update** a module, nor **enroll** a new service/host. This RFC fills
exactly that.

## 4. `node.package` (proposed code 109)

Manager→Agent. Handled by the target host's roxyd.

Names are **package-generic**, not module-specific: `node.package`
delivers modules (Piglet, …) **and** core components (REView,
aice-web-next, roxyd) alike (RFC-B, RFC-D2 §4e).

```rust
pub enum NodePackageRequest {
    /// Install or update a package — a module ("piglet") or a core
    /// component ("review"/"aice-web-next"/"roxyd"). The signed `.pkg`
    /// bytes follow on the same bi-stream (see streaming). The request
    /// carries routing, size, and — on a first install — the enrollment
    /// material, but deliberately NOT the manifest or signature: the
    /// single source of trust is the manifest + signature INSIDE the
    /// `.pkg` (bootler RFC 0004 §4-§5); see verification below.
    Install {
        // host-agnostic package id (= manifest component); RFC-A §4 registry
        target: String,
        /// Which instance of `target` on this host to place: a number
        /// scoped by `{target}.{host}`, allocated by the manager
        /// (RFC-A §4). The agent CANNOT derive it — the allocation is the
        /// manager's — and it needs it to pick the unit name, the paths,
        /// and the state it writes, which are what keep two instances of
        /// one module from colliding (RFC-B §4). `None` for a component
        /// whose class has no instance dimension (the core components).
        /// In v1 this is `Some(1)` for a module and `None` for a core
        /// component: RFC-A §4 pins the number and defers allocating others,
        /// so the field is carried from the first release and only the range
        /// of accepted values widens later.
        /// The composed `registration_id` is NOT sent: that belongs to the
        /// enrollment plane and the registrar derives it (RFC-F §5.5).
        instance: Option<u32>,
        // expected version (opaque display token, RFC-A §4); MUST match the manifest
        version: String,
        // expected git commit SHA; MUST match the manifest (exact build id)
        commit: String,
        size: u64,        // byte length of the streamed `.pkg`
        /// Stable id for THIS operation, carried so a re-sent or resumed
        /// request is recognized as already-applied. The agent decides this
        /// **at the preflight step, before any bytes stream** (see the
        /// streaming state machine): a repeat of an already-completed
        /// `idempotency_key` (or exact build) returns `AlreadyApplied` and the
        /// client sends no `.pkg`. Equals REView's
        /// `operation_attempt.idempotency_key` (RFC-D2 §4d). (How resume
        /// authority is arbitrated between REView's re-drive and roxyd's own
        /// durable job is fixed in RFC-B §8 / RFC-D2 §4b; this field is the wire
        /// slot that makes the preflight no-op possible.)
        idempotency_key: String,
        /// Per-service bootroot enrollment material, minted by the
        /// registrar via `node.enroll` (§5) and relayed here — the SAME
        /// `BootstrapMaterial` that `node.enroll` returns. `Some` on a
        /// FIRST install that needs its own mTLS identity; `None` on an
        /// update, or a package whose identity already exists (e.g. core
        /// components). The agent bootstraps with it BEFORE placing the
        /// package (RFC-B §5).
        bootstrap_material: Option<BootstrapMaterial>,
        /// What the agent does if the new version fails its health gate
        /// (RFC-B §8). REView sets it from the operator's choice; default
        /// `Rollback`.
        on_failure: FailurePolicy,
    },
    /// Remove one installed instance (stop unit, remove artifacts).
    /// `instance` selects which, exactly as on `Install`.
    Remove {
        target: String,
        instance: Option<u32>,
        idempotency_key: String,
    },
    /// List installed packages and their `(version, commit)` build ids.
    /// Each entry carries its `instance`, so two instances of one module
    /// are distinguishable.
    ListInstalled,
    /// Report install/lifecycle state of one installed instance.
    Status { target: String, instance: Option<u32> },
}

/// `Install` preflight — the agent's FIRST reply, sent AFTER the framed
/// request and BEFORE any `.pkg` bytes, so the client only streams when
/// needed.
pub enum InstallPreflight {
    // agent needs the package: client streams bytes, then agent sends a
    // NodePackageResponse
    Proceed,
    // already installed AND the unit is not failed: THIS frame is the
    // terminal success — no bytes, and no following NodePackageResponse.
    // The health condition is deliberate: identity alone would make a
    // Failed-but-installed build permanently un-re-appliable (see §4).
    AlreadyApplied,
    // the agent cannot fit `size` on the filesystem it would stream into.
    // Decided from the request alone, so NO bytes move and nothing on the
    // host is touched; terminal, and NOT retryable until an operator frees
    // space (see §4). Carries the filesystem, the space required and the
    // space available so the report names a cause.
    InsufficientDiskSpace { filesystem: String, required: u64, available: u64 },
}

pub enum NodePackageResponse {
    // terminal success of an APPLIED install/remove (the Proceed path);
    // NOT sent after AlreadyApplied
    Done,
    // self-disrupting apply (the target is roxyd's OWN binary, or the manager
    // REView itself): the swap tears down this response channel, so the agent
    // sends this BEFORE the swap — after verify + durable stage — and no later
    // Done can follow; the true outcome (Running/Failed) is reconciled from
    // REView's operation_attempt on reconnect (RFC-B §8, RFC-D2 §4e)
    Accepted,
    // terminal success of a `trust` target apply. Carries the epoch the agent
    // is ACTIVE ON after activating, so the manager confirms a trust rollout
    // IN-CONNECTION rather than waiting for the next handshake AgentInfo — an
    // agent that stays connected for weeks would otherwise never report its
    // new epoch (RFC-D2 §4a).
    TrustActive { active_epoch: u64 },
    Installed(Vec<InstalledPackage>),  // for ListInstalled
    State(PackageState),               // for Status
}

/// What the agent does if the newly-applied version fails its health gate
/// (RFC-B §8). Set by REView from the operator's choice.
pub enum FailurePolicy {
    Rollback,  // restore the previous version (default — favor availability)
    Hold,      // leave the failed version in place, report it (favor diagnosis)
}

/// One installed instance. `ListInstalled` returns one per instance, so two
/// instances of one module are distinguishable.
pub struct InstalledPackage {
    pub target: String,
    pub instance: Option<u32>,
    pub state: PackageState,
}

/// Install/lifecycle state of ONE instance, as the agent observes it:
/// `(version, commit)` from the on-disk apply record, run-state recomputed
/// from systemd (RFC-B §9).
pub struct PackageState {
    pub version: String,
    pub commit: String,
    /// The instance's install/run state. Defined below rather than
    /// referenced, because it is a wire type this crate must encode.
    pub lifecycle: Lifecycle,
    /// The addresses this instance is ACTUALLY LISTENING ON, read from the
    /// host's live sockets — not from its configuration file, which can say
    /// something else until the service restarts. Empty for a component
    /// that listens on nothing, which is every module except Giganto: the
    /// four agents dial out on an ephemeral port and bind no service address
    /// (RFC-A §4). They are **reported, never accepted**: the manager
    /// records them (RFC-D1) and never tells the agent what to bind. v1
    /// chooses no addresses (RFC-B §4); the field exists so that when a
    /// later release does choose them, the wire does not change.
    pub bound_addrs: Vec<BoundAddr>,
}

pub struct BoundAddr {
    /// The configuration key this address belongs to, so the manager and UI
    /// can match it without positional assumptions — e.g. `graphql_srv_addr`.
    pub name: String,
    pub addr: String,  // host:port, as bound
}

/// Install/run state of one instance, as the agent observes it. The manager
/// persists the same set of VARIANTS (RFC-D1), but the two encodings are
/// independent: that is a storage type in another crate, and the manager
/// maps between them. The values are enumerated HERE because they cross
/// this wire and must round-trip: a decoder built from this family alone
/// has to know every variant, including the two an agent rarely sends.
/// `Unknown` is the forward-compatible sentinel — a manager that receives
/// a state a newer agent introduced maps it here instead of failing the
/// decode. The derives below are what make that true; a plain derive would
/// not (see the decision after this block).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[derive(num_enum::FromPrimitive, num_enum::IntoPrimitive)]
#[serde(from = "u8", into = "u8")]
#[repr(u8)]
pub enum Lifecycle {
    NotInstalled = 0,
    Installing = 1,
    Running = 2,
    Stopped = 3,
    Failed = 4,
    Removing = 5,
    /// Any discriminant this build does not know decodes here.
    #[num_enum(default)]
    Unknown = u8::MAX,
}
```

- **[DECISION] `Lifecycle` rides the wire as its `u8` discriminant, and an
  unrecognized value decodes to `Unknown`.** The sentinel is only real if a
  decoder can reach it, and a plain `#[derive(Deserialize)]` cannot: bincode
  encodes a derived enum by **variant index**, so a state a newer agent
  introduced fails the decode outright and `Unknown` is never produced —
  exactly the forward-compatibility the comment claims. `serde_repr` alone
  does not close it either: `Deserialize_repr` **errors** on an unmatched
  discriminant rather than falling back. So the type carries `#[repr(u8)]`
  with explicit discriminants, `#[serde(from = "u8", into = "u8")]`, and
  `num_enum::FromPrimitive`/`IntoPrimitive` with `#[num_enum(default)]` on
  `Unknown`. Both crates are already dependencies (`Cargo.toml`:
  `num_enum = "0.7"`, `serde_repr = "0.1.19"`) and both idioms already
  appear here — `#[repr(u8)]` with `Serialize_repr`/`Deserialize_repr` on
  `LabelDbKind` (`src/types.rs:168`), `#[serde(into = "u16",
  try_from = "u16")]` (`types.rs:77`), and `FromPrimitive` with
  `#[num_enum(default)]` (`client.rs:19`/`:121`, `server.rs:247`/`:283`).
- **[DECISION] These discriminants and review-database's are NOT one
  encoding.** `Lifecycle` exists in two crates: this wire type, and
  review-database's storage type (RFC-D1 §4a), which follows that repo's
  `Status` house style — `#[repr(u8)]` plus num-derive `FromPrimitive`,
  `Unknown = u8::MAX` (`src/tables/node.rs:9-41`). That type's serde derive
  is **plain**, so its stored bincode value is the variant index, not the
  discriminant. The two encodings are independent by design and the manager
  maps between them; no code may read a number written on one side as
  meaning the same on the other. Giving both `Unknown` the value `u8::MAX`
  is a readability convenience, not a contract.

- **[DECISION] Streaming state machine with a preflight ACK — exact wire
  sequence.** On the `Install` bi-stream, frames go in this fixed order, and
  **each branch has exactly one terminal frame** so neither side ever blocks
  waiting for a frame that will not come:
  1. **client → agent:** the framed `Install` request message (the enum
     above; no bytes yet).
  2. **agent → client:** an **`InstallPreflight`** — decided from the framed
     request alone (`idempotency_key` + `(target, version, commit)`):
     - **`AlreadyApplied`** — the build is already installed **and its unit is
       not in a failed state**. **This frame is
       the terminal response: the client sends NO `.pkg` bytes, and the agent
       sends NO subsequent `NodePackageResponse`.** The exchange ends here.
       (This is the idempotent no-op — no re-upload, no half-streamed payload
       stalling flow control.)
       **[DECISION] The health condition is part of the predicate, not an
       afterthought.** Keyed on build identity alone, a module that installed
       cleanly but whose unit **failed to start** (bad config, missing
       dependency, `lifecycle = Failed`) can never be re-applied: the operator
       fixes the cause, clicks Update on the same build, and gets `Proceed`-less
       success — no bytes, no `enable --now`, and the operation recorded as a
       **successful update over a still-Failed service**. The only escape would
       be uninstall + reinstall, which drags in the two-step deregister, a
       re-mint, and the re-registration block — a punishing path for what is
       really "try that again." So the agent returns `AlreadyApplied` only when
       the build is installed **and** its current unit state is not `failed`;
       otherwise `Proceed`, and the diff engine makes the re-apply a cheap
       no-op plus a unit restart. The same reasoning covers a `Hold`-ed failed
       update, where the failed build is what is installed.
     - **`Proceed`** — go to step 3.
     - **`InsufficientDiskSpace`** — the agent cannot fit `size` on the
       filesystem it would stream into. **Decided at preflight, so no bytes
       move**: `size` is on the request, so refusing here saves transferring
       a multi-hundred-megabyte package to a host that provably cannot accept
       it — which matters most for the large core-component images this path
       carries, over the slow links it carries them on. This is the cheap
       staging-only check; the agent still runs the full per-destination check
       before its first mutation (RFC-B §4), because the install target and the
       container runtime's storage root are usually different filesystems and
       their requirement is not known until the package is verified. Like the
       apply-time form, it is **not retryable** without operator action.
  3. **(Proceed only) client → agent:** the `.pkg` bytes over the **same QUIC
     bi-stream** as length-prefixed chunks (following the
     `process_event_stream` precedent — header/first message, then read the
     raw `RecvStream`), avoiding a multi-hundred-MB single bincode message.
     The agent reads exactly `size` bytes to a temp path.
  4. **(Proceed only) agent → client:** a single terminal
     **`NodePackageResponse`** after verify + apply — **`Done`** on success (or
     an error) for an apply where **both stream endpoints survive it**.
     **Exception — a self-disrupting apply** (the target is roxyd's **own**
     binary, or the manager **REView** itself, so the swap tears down this
     response channel): the agent cannot send a post-swap frame, so its terminal
     frame is **`Accepted`**, sent after verification + durable staging but
     **before** the disruptive swap. There is **no** following `Done`; the
     authoritative outcome (`Running`/`Failed`) is reconciled from REView's
     pre-written `operation_attempt` on reconnect (RFC-B §8, RFC-D2 §4e). (An
     aice-web-next update, where both endpoints survive, takes the normal `Done`
     path.)

  So: **`AlreadyApplied` terminates at step 2 with no `NodePackageResponse`;
  `Proceed` ends with exactly one terminal frame at step 4 — `Done` for a
  survivable apply, or `Accepted` (sent before the swap) for a self-disrupting
  one.** On `Proceed`, any short read, chunk-frame error, or stream reset during
  step 3 **aborts** the transfer and the agent returns an error response at
  step 4 (the whole `.pkg` is re-sent on the next retry — no partial resume in
  v1).
- **[DECISION] Verification (before any apply).** The agent trusts **only
  the manifest + signature inside the received `.pkg`** (bootler RFC 0004
  §4-§5) — never the request. It verifies, in order: (a) the signature
  over the in-package manifest; (b) each artifact's `sha256` against the
  manifest; (c) that the in-package manifest's **`component`, `version`,
  and `commit` equal the request's `target`, `version`, and `commit`**
  (RFC-A §4's package-identity rule) — any mismatch is `TargetMismatch`.
  Only then does it apply.
- **[DECISION] Apply order (strict).** Every side effect happens **after**
  verification succeeds, in this order: **(1)** stream to a temp path;
  **(2)** verify (signature → hashes → target/version, above); **(3)** if
  `bootstrap_material` is `Some`, run the bootroot enrollment/bootstrap
  (RFC-B §5) — bootstrap is itself a side effect, so it never precedes
  verification; **(4)** apply via `deploy-core`'s diff engine (RFC-B),
  per-artifact `stop→swap→start` with `.previous` backup
  (`install = update`, no separate "update" code).
- **[DECISION] `bootstrap_material` presence rule.** A **first install** of
  a module with no existing identity **requires** `bootstrap_material`; if
  it is `None`, the agent rejects the request with
  `MissingBootstrapMaterial` (before any apply). On an **update**, or a
  package whose identity already exists (core components), `None` is
  expected — a stray `Some` there is ignored.
- **[DECISION] `InsufficientDiskSpace` is a distinct, NOT-retryable apply
  failure.** The agent checks free space on every filesystem the apply will
  write to before its first mutation (RFC-B §4) — a container image holds the
  tar and the loaded image at once, a binary apply holds `.previous` and the
  new artifact at once — and refuses with this error, carrying the filesystem,
  the space required, and the space available. It is typed rather than a
  generic apply failure because the **manager must not retry it**: unlike a
  transient transport error, re-driving changes nothing until an operator frees
  space, so it terminates the attempt instead of burning the retry budget
  (RFC-D2 §4b), and the UI can state the actual remedy (RFC-E §9).
- **[DECISION] Expired material is a DISTINCT error meaning "re-mint and
  resume", not "abandon".** The material is minted **before** `deploy` and is
  consumed only at step (3), after a multi-hundred-MB package has streamed and
  been verified — so on a slow or congested link the wrap TTL can lapse
  mid-transfer. If that surfaced as a generic enrollment failure, REView would
  discharge the compensation, the operator would retry, and the same timing
  would recur: a **deterministic livelock** for that host, reported as an
  enrollment problem rather than a transfer-duration one. So the agent returns
  **`BootstrapMaterialExpired`**, which REView treats as re-mint-and-resume —
  the **identity is intact**, only the wrapped credential lapsed, so tearing it
  down would be wrong. REView requests a generous wrap TTL with a documented
  floor rather than one derived from package size (RFC-D2 §4d); deriving a TTL
  from size and an assumed throughput is wrong on both ends and adds a
  configuration knob for no gain.
- **[DECISION] No intermediate progress in v1.** `Install` returns a
  single terminal `NodePackageResponse` — there is **no phase/progress
  event stream** from the agent during the apply. REView therefore tracks
  only the coarse lifecycle transitions it drives (`operation_attempt.phase`
  at the boundaries it controls, RFC-D1 §4d); the internal verify → enroll →
  start sub-steps are reported only via the terminal result. Continuous
  sub-step emission (agent → manager phase frames on the bi-stream) is a
  **post-v1** extension (RFC-E §10).
- **[DECISION] Reserved `trust` target — runtime trust-set delivery.** A
  reserved `target = "trust"` delivers a **release-signing trust-set
  generation** (public keys by `key_id` + revoked-`key_id` list +
  withdrawn-build list — bootler RFC-A §5), not an installable component.
  It streams like any package but is **verified against the *current*
  active trust generation** and then **activated as the next generation**
  by the agent (into the release-signing trust tree, reusing the
  `roxyd_trust` activation) — this is how keys/revocations/withdrawals are
  updated at runtime with bootler gone. The generation carries a **signed,
  strictly-monotonic `epoch`** (RFC-A §5): the agent activates it **only if
  its `epoch` is strictly greater than the active generation's**, else
  rejects it (`StaleTrustSet`) — so an older validly-signed generation
  cannot be replayed to restore a revoked key or drop a withdrawn build.
  `trust` is **not** in the RFC-A §4
  UI package-id registry, carries no `bootstrap_material`, and is never
  routed from a UI install/update action — only from REView's trust-plane
  management.
- **[DECISION] A `trust` apply ACKs the agent's resulting epoch in-connection.**
  Both outcomes report the epoch the agent is **actually active on**: a
  successful activation returns `TrustActive { active_epoch }`, and a
  `StaleTrustSet` rejection carries the agent's current `active_epoch` too. The
  handshake `AgentInfo.active_trust_epoch` (§6) is exchanged **once per
  connection**, so it alone cannot confirm a rollout to a long-lived
  connection — the manager would re-push forever to an agent that already
  activated. With this ACK the manager has a per-apply ground-truth reading and
  `StaleTrustSet`-on-equal becomes an explicit **already-at-this-epoch**
  confirmation rather than an inference from delivery bookkeeping (RFC-D2 §4a).
- **[DECISION] Trust generations carry a package identity like any other
  `.pkg`.** The in-package manifest sets `component = "trust"`, `version` =
  the generation's decimal `epoch`, and `commit` = the generation digest, so
  the §4 verification chain — signature → hashes → **`TargetMismatch`** on
  identity mismatch — applies unchanged to the highest-privilege channel.
  Without this the `trust` target would be the one package the identity check
  does not cover, and a generation minted for one deployment could be replayed
  into another sitting at a lower `epoch`. `trust` remains outside the RFC-A §4
  **UI** registry (it is not UI-installable); this is a manifest identity, not
  a registry entry.
- **Chunk size and backpressure are sender-side tuning, not wire contract**
  — the agent reads exactly `size` bytes, so how the sender chunks is not
  observable to it (§7). Recovery is decided: restart-whole in v1.
- **ServiceId:** `node.package`, `node.package.install`,
  `node.package.remove`, `node.package.list`, `node.package.status`.

## 5. `node.enroll` (proposed code 110)

Manager→Agent, **directed at the registrar agent** (the
bootroot-co-located roxyd; bootler RFC 0004 §6). Small/unary — no
streaming.

```rust
pub enum NodeEnrollRequest {
    /// Register a new service in bootroot and return its bootstrap
    /// material. Used for BOTH per-service install and new-host
    /// onboarding (host self-join; the new host's own roxyd).
    ///
    /// The request carries the identity's PARTS, never a composed name:
    /// the registrar derives both the certificate name and bootroot's
    /// namespace key from them (RFC-F §5.1/§5.5), so there is no
    /// caller-supplied composed value for the two sides to disagree on.
    Register {
        /// The component's PLAIN keyword — `piglet`, `roxyd` — a single
        /// DNS label, never host- or instance-qualified. It is the SAN's
        /// service segment (RFC-A §4).
        service_name: String,
        delivery_mode: DeliveryMode, // local-file | remote-bootstrap
        /// The target host's single DNS label — the SAN's host segment.
        host: String,
        /// Which instance of `service_name` on `host` this is: a number
        /// scoped by `{service_name}.{hostname}`, allocated by the manager
        /// (RFC-A §4, RFC-D2 §4d). `None` for a component whose
        /// multiplicity class has no instance dimension — the core
        /// components — which take the default `001`. Only the five
        /// modules are multi-instance (RFC-A §4).
        instance: Option<u32>,
        /// The registration spec the registrar applies on a first mint AND
        /// compares against the existing one on a re-register (the spec-match
        /// / `ServiceSpecConflict` rule below). It mirrors the **bootler**
        /// `ServiceRegistration` shape (`core/src/product.rs:730`:
        /// `component`, `service_name`, `reload`, `cert_group`) — NOT a
        /// bootroot type; bootroot has no such symbol. Those four fields are
        /// the whole shape: there is deliberately **no privilege field**
        /// (RFC-A §4), because bootroot always derives a service's authority
        /// from the fixed `bootroot-service-<name>` policy. The registrar
        /// safe-set validates `cert_group` and `reload` (RFC-F §5.1).
        /// **Provenance:** the
        /// Manager (REView) derives it from the component's package-declared
        /// `ServiceRegistration` (RFC-A §4) and carries it here, so the
        /// registrar has a concrete spec to compare — it is NOT re-derived by
        /// the registrar. The identity is `(service_name, host, instance)`;
        /// `spec` is what that identity is registered *as*.
        spec: ServiceSpec,
        /// Requested lifetime of the wrapped material. The registrar MAY
        /// clamp it to its own maximum; the GRANTED absolute deadline comes
        /// back in `BootstrapMaterial::expires_at`. Without this on the wire
        /// the manager has no way to compute the durable `expires_at` that
        /// RFC-D1 §4d persists and RFC-E §6 displays.
        wrap_ttl: Duration,
        // correlate a re-driven mint (see below + RFC-D2 §4d)
        idempotency_key: String,
    },
    /// Deregister a service on uninstall: tear down its bootroot AppRole,
    /// policy, per-service KV, and state entry (bootler runs `bootroot
    /// service remove`, which bootroot supports), so no orphaned identity
    /// or cert lingers.
    Deregister {
        service_name: String,
        host: String,
        /// Same meaning as on `Register` — the registrar derives the same
        /// namespace key from it and refuses a teardown whose host does
        /// not match the one bound to that key (RFC-F §5.2).
        instance: Option<u32>,
        idempotency_key: String,
    },
}

/// The registration shape the registrar applies / compares. Mirrors the
/// bootler `ServiceRegistration` (`core/src/product.rs:730`) exactly —
/// these four fields are the whole shape. There is deliberately **no**
/// privilege field (RFC-A §4): bootroot always derives a service's authority
/// from the fixed `bootroot-service-<name>` policy, so no component differs
/// on that dimension. The registrar safe-set validates `cert_group` and
/// `reload` (RFC-F §5.1).
pub struct ServiceSpec {
    component: String,      // canonical package-id (RFC-A §4)
    service_name: String,   // the component's plain keyword (RFC-A §4)
    reload: ReloadHook,
    cert_group: Option<CertGroup>,
}

/// How the minted material reaches the target. Decided per target kind by
/// the caller (RFC-B §5): modules and new hosts enroll through bootroot's
/// on-host agent, so REView sends `RemoteBootstrap` (RFC-D3 §5a).
pub enum DeliveryMode {
    LocalFile,        // material placed on the host out of band
    RemoteBootstrap,  // bootroot-remote enrollment via the on-host agent
}

/// What the target consumes to obtain its certificate — bootroot's existing
/// `bootstrap.json` shape (`bootroot-remote/bootstrap.rs`): the AppRole
/// `role_id`, the response-wrapped `secret_id`, and the CA anchor. This is
/// the SERVICE's enrollment material and is unrelated to how the registrar
/// itself authenticates to bootroot (RFC-F §4). `expires_at` is the GRANTED
/// absolute deadline after any registrar clamp of the requested `wrap_ttl`.
pub struct BootstrapMaterial {
    role_id: String,
    wrapped_secret_id: String,
    ca_anchor: Vec<u8>,
    expires_at: DateTime<Utc>,
}

pub enum NodeEnrollResponse {
    /// Wrapped bootstrap material the target consumes to obtain its cert
    /// (role_id + wrapped secret_id + CA anchor), i.e. bootstrap.json.
    /// Carries `expires_at`: the GRANTED absolute deadline of the wrapped
    /// secret_id, after the registrar has applied any clamp to the requested
    /// `wrap_ttl`. The manager persists it (RFC-D1 §4d) so the expiry clock
    /// survives a restart, and the UI displays it (RFC-E §6). The manager
    /// MUST NOT assume it equals what it requested.
    Material(BootstrapMaterial),  // for Register
    Done,                         // for Deregister
}
```

- **[DIRECTION] Semantics.** The registrar roxyd invokes bootroot's
  **restricted mint verb** locally (RFC-F §4/§5.1; RFC-A §6) and returns the
  wrapped material. It does **not** author roles or policies itself — the
  derivation, safe-set validation, label/host re-derivation, collision check
  and spec-match all run inside the verb under bootroot's own credential,
  which is what keeps a compromised registrar from minting itself new
  authority (RFC-F §3/§4).
  The manager relays that material to the target host's roxyd — as the
  `bootstrap_material` field of the module's `node.package` `Install`
  (§4), or as the operator's onboarding join token for a new host.
- **[DECISION] Boundary + verbs.** The restricted mint / deregister calls are
  roxyd↔bootroot **local** operations, not review-protocol messages;
  this family is the
  **manager→registrar** command + result. It carries **`Register`** (mint)
  and **`Deregister`** (tear down on uninstall — bootroot supports
  `service remove`), so no orphaned identity/cert lingers. The registrar
  policy gains `delete` for `Deregister` (bootler RFC 0004 §6).
- **[DECISION] Both verbs are idempotent (crash-safe re-drive).**
  - **`Deregister`** — tearing down an already-absent identity **for the
    matching host** returns `Done`, not an error, so REView can re-drive an owed
    deregister after a crash (RFC-D2 §4d). A **wrong-host** `Deregister` (the
    requested `host` is not the identity's registrar-bound host, RFC-F §5.2) is
    **refused with a DISTINCT typed error `ServiceHostMismatch`** (not a generic
    or transient failure), never a `Done` teardown — so a collision-cleanup for
    one host can never remove another host's identity, **and** REView can tell
    the host-verified refusal apart from a transient registrar/network error: it
    **discharges** the owed teardown on `ServiceHostMismatch` (this host owns
    nothing) but **retries** on a transient error (RFC-D2 §4d), so a real owed
    teardown is never dropped and a genuine refusal never loops.
  - **`Register`** — idempotent on a **matching spec**, an **error on a
    conflicting** one. For an already-registered `service_name` the registrar
    **compares the existing role/policy/registration spec against the
    requested one**: on a **match** it **does not error and does not
    double-mint** — it **re-issues fresh wrapped material for the same
    identity** (role and policy already exist and are reused; a **new wrapped
    `secret_id`** is minted and returned); on a **conflict** (same
    `service_name`, different spec — `cert_group` or `reload`) it
    returns **`ServiceSpecConflict`** and mints **nothing**, so a stale or
    wrong-shape service is never silently re-issued fresh material. The
    matching case is what makes a first-install crash between mint and a
    completed `node.package` `Install` recoverable: the wrapped `secret_id` is
    single-use and short-TTL and is **not** persisted anywhere (never stored
    in the operation ledger), so resume cannot replay the old material — it
    **re-mints** it. The existence probe that distinguishes "already exists →
    spec-check → re-wrap" from "new → create" runs **inside** bootroot's
    restricted mint verb, not in roxyd (RFC-F §4–§5, RFC-B §6).
  - **[DECISION] `ServiceNameCollision` is a THIRD typed enroll error, defined
    here.** Two other documents already depend on it by name — RFC-F §5.1
    rejects a derived `registration_id` already bound to a *different* host
    with it, and RFC-E §6 shows it as an actionable error with remediation —
    but this family owns the wire
    types, so it must exist here or the rejection arrives at the manager as a
    **generic** error and review **retries it as transient**: exactly the
    failure mode `ServiceHostMismatch` was made distinct to avoid, and RFC-E's
    "show the remediation" criterion becomes unmeetable. Like
    `ServiceSpecConflict` and `ServiceHostMismatch`, it is **distinct from a
    transient failure** — the manager must never retry it — and it is raised
    **before** the spec-match (RFC-F §5.1's ordering requirement). There is
    **no** companion "name does not match the host" error: this family
    carries the identity's parts and the registrar derives the composed name
    from them (RFC-F §5.5), so no caller-supplied name exists to disagree
    with the host — the mismatch that error would have caught cannot be
    expressed.
  - **[DECISION] `ServiceInstanceMismatch` is a FOURTH typed enroll error,
    for an `instance` that contradicts the component's multiplicity.**
    Deriving the `registration_id` picks one of three arms by multiplicity
    class (RFC-A §4), so the registrar validates that `instance` is
    **present** for a many-per-host component and **absent** for a
    one-per-host or one-per-deployment one, refusing otherwise (RFC-F §5.1).
    That refusal needs its own type for the same reason
    `ServiceNameCollision` does: it is **deterministic**, so a manager that
    receives it as a generic error retries it until the apply budget is
    spent, terminates `Failed` with the teardown still owed, and reports no
    cause. It is raised **before** any mint, so nothing is created. Like the
    three above, the manager must **never** retry it, and RFC-E §9 carries
    its remediation line.
  - **[DECISION] `Register` is idempotent in EFFECT, and always returns FRESH
    material — the `idempotency_key` is NOT a material cache.** These two must
    not be conflated: because the registrar **does not persist** the
    `secret_id`, it **cannot** return the *same* bytes on a re-drive — so
    `idempotency_key` does **not** mean "return the cached response." Its only
    job is to let the registrar and REView's ledger **correlate retries of one
    logical operation** — so a re-drive is recorded as the same
    `operation_attempt`, not a second one, and audit/mint events are not
    double-counted. Every successful `Register` (first or re-driven) returns a
    **new** wrapped `secret_id` for the (matching-spec) identity; a
    previously-issued, unconsumed `secret_id` is simply **abandoned** (harmless
    — single-use, short-TTL). This is coherent because the *identity* (role +
    policy) is idempotent (probe + spec-match) while the *credential* is
    deliberately fresh each time. There is therefore **no durable
    per-key material state** to keep; the only durable state is the bootroot
    identity itself and REView's `operation_attempt` keyed by `idempotency_key`
    (RFC-D2 §4d), which records the operation's progress, not the secret.
- **ServiceId:** `node.enroll`, `node.enroll.register`,
  `node.enroll.deregister`.

## 6. Version negotiation and compatibility

- **[DECISION] Additive.** Codes 109/110 are new; all existing `node.*`
  and legacy codes are unchanged. An agent that does not implement them
  hits the existing default arm and returns "unknown request code," so
  old agents fail closed rather than misbehaving.
- **[DECISION] Capability-gated routing + a wire/protocol version bump.**
  The manager records each agent's advertised capabilities at connect and
  **routes `node.package`/`node.enroll` and role-scoped actions only to the
  agents that carry them.** The wire/protocol version is bumped when the
  capability field is added. **Because the field decodes tolerantly from v1.0
  (§7), an agent that does not advertise a capability — whether an initial
  single-version peer or a later not-yet-updated one — decodes to an empty set,
  stays connected, and is simply never sent the codes it lacks** (and still
  fail-closes on its default arm if sent one). The durable job of the
  capability set is **role routing** (which roxyd is the registrar, which is
  co-located with review / aice-web-next), which is version-independent.
- **[DECISION] Handshake capability metadata.** The agent advertises its
  capabilities in the handshake `AgentInfo` as a **composable set** —
  `registrar`, co-location (`review`/`aice-web-next`), and
  `node.package`/`node.enroll` support — so the manager routes each concern
  to the agent that carries it, **atomically at connect** (one roxyd may
  hold several roles at once — RFC-B §9, RFC-D2 §4c), not via a post-connect
  message.
- **[DECISION] Encode the set as namespaced string tags** —
  `capabilities: BTreeSet<String>` on `AgentInfo`
  — **note the crate already has an unrelated `capabilities`**:
  `ProtocolMetadata { version, capabilities: Vec<String> }` (`src/auth.rs:234`,
  "capability tokens advertised by the peer"), attached to
  `AuthorizationContext`. Different type, different container, not on the
  handshake struct — so the absence-claim for `AgentInfo` holds, but an
  implementer will meet two `capabilities` concepts and must not conflate them.
  Whether they should eventually converge is out of scope here
  (`src/lib.rs:166`, `derive(Serialize, Deserialize)`) with tags like
  `registrar`, `colocated:review`, `colocated:aice-web-next`,
  `node.package`, `node.enroll` — **not** a fixed struct of one bool per
  role. Chosen for **extensibility and composable roles**: a future
  capability is just another tag, so it needs **no further wire change**,
  and the manager **validates the tags it knows and ignores the rest**. A
  per-role bool struct would make each new capability its own wire field.
  Security-sensitive tags (`registrar`, `colocated:*`) stay
  **advertised-not-authoritative** and are corroborated against the
  bootler-provisioned placement + mTLS identity before any privileged action
  (RFC-D2 §4c). The field is added **at the `AgentInfo` tail with tolerant-tail
  decode in v1.0** (§7), so the capability dimension is **forward-compatible
  from the start** — a peer that omits it decodes to an empty set, and an older
  decoder ignores the trailing bytes.
- Both `client` (agent) and `server` (manager) feature sides gain the
  new request/handler surface.

## 7. Remaining details and in-repo ratification

**No design question in this RFC is open.** Two items previously listed here
were miscategorized and are closed below; the third is an ownership pointer,
not a question.

- **Code assignments 109/110 — ratified by merging this RFC.** This is an
  `aicers/review-protocol` maintainer decision with no external gate, and the
  evidence is already in: §2 verifies 109-110 are unused, and the round-trip
  tests that pin the numeric mapping (`request.rs:1069`, `:1056`) fail if the
  assignment ever collides. Merging this document **is** the ratification;
  nothing further is pending.
- **Chunk size and backpressure are NOT on the wire contract.** What is
  contractual is the framing: length-prefixed chunks on the raw `RecvStream`,
  and **the agent reads exactly `size` bytes** (§4). The receiver therefore
  does not observe how the sender chunks, so chunk size is a sender-side
  buffer choice an implementation tunes freely — it was never a protocol
  question, and fixing a number here would constrain implementations for no
  interop gain. (Recovery is decided: restart-whole, §4.)
- The **`.pkg` envelope** definition is a single shared spec **owned by**
  bootler RFC 0004 §4-§5 (manifest + signature layout, `key_id`), which roxyd
  and REView both verify against; this crate references it and does not
  redefine it. The verification-input contract (signed bytes = manifest,
  `key_id` in the envelope, revoked-key handling, error codes) is fixed
  jointly with RFC 0004 §5. This is an ownership boundary, not an open item.
- **[DECISION] `AgentInfo` capability field — added at the tail with
  tolerant-tail decode in v1.0.** (The implementation issue is decomposed from
  this RFC — §6; it is a small, self-contained change, not a standalone gate.)
  `capabilities: BTreeSet<String>` is appended at the **tail** of `AgentInfo`
  and both sides decode it **tolerantly from v1.0**: decode the base
  `AgentInfo`, then **conditionally decode the capability tail from any leftover
  bytes** (empty set if none). This makes the capability dimension
  forward-compatible from the first release, so an operator using v1's ability
  to update **one** component independently (`updateCoreComponent` for REView
  alone — RFC-D2 §4e, RFC-E §5) can create a version skew **without** bricking
  the handshake: a manager that meets a not-yet-updated agent (or vice versa)
  still decodes cleanly.
  - **Why not a naive field.** A plain `#[serde(default)]` sixth field does
    **not** work — `AgentInfo` is bincode (positional, non-self-describing), so
    an old agent omitting the field makes a decoder that expects it read past
    the buffer and fail (`UnexpectedEnd`). Hence the explicit **base +
    conditional-tail** decode. The reverse direction (extra trailing bytes) is
    already safe: `oinq::frame::recv` (`borrow_decode_from_slice`) discards
    bytes past the decoded struct and the frame is length-delimited.
  - **Fail closed on a corrupt tail — do NOT fall back to empty.** "Empty set
    if no tail" applies **only** when there are **no** leftover bytes. If the
    tail is **present but does not decode** (truncation/corruption), the
    handshake **fails** — it must **not** be silently treated as an empty set.
    A silent empty-fallback would both mask corruption and, worse, drop a
    security-relevant claim: a peer that *should* advertise `registrar` /
    `colocated:*` but whose tail is corrupted would decode to empty, and
    corroboration (RFC-D2 §4c) only rejects *false* claims — it does not alarm on
    a **missing-but-expected** one — so the loss would be invisible. **The
    `AgentInfo` tail is exchanged inside the QUIC+mTLS-protected `oinq::frame`
    stream (after the handshake), so an on-path attacker cannot selectively
    corrupt it to force a specific agent's fail-closed drop — a byte-flip breaks
    the AEAD tag (the packet is dropped by QUIC, never delivered as a "corrupt
    tail"), and truncation is caught by the length-delimited framing.** So
    fail-closed here fires only on a genuine bug/storage corruption, and a
    corrupt-tail stall degrades to an availability issue, never a silent breach.
  - **Acceptance (three cases tested).** **(1) old peer → new decoder**: a
    handshake with no capability tail decodes to an **empty** capability set
    (the agent stays connected, is simply sent none of 109/110). **(2) new peer
    → old decoder**: a handshake carrying the capability tail **does not fail**
    the decode (extra bytes ignored). **(3) forward-field**: a handshake with
    the capability tail **followed by a second, later tail field** is decoded by
    a capabilities-only decoder to the **correct** capability set with the later
    field **ignored** — this proves the decode consumes exactly its own bytes
    (a naive whole-slice `decode_from_slice` that asserts full consumption would
    pass (1)/(2) but break here, defeating the forward-compatibility claim).
  - **Future fields** follow the same discipline — append at the tail, extend
    the conditional-tail decode, each field consuming exactly its own bytes — so
    no separate cross-version gate is needed; landing the pattern in v1.0 is
    what removes the risk, rather than a note deferred to a later release.
- **[DECISION] `AgentInfo` also carries the agent's ACTIVE release-signing
  trust-set `epoch`** — a second tail field (`active_trust_epoch: u64`),
  appended after `capabilities` and decoded by the same conditional-tail
  discipline (this is exactly the "second, later tail field" acceptance case (3)
  above). The manager needs the roxyd's **self-reported** active `epoch` so the
  trust-set rollout completeness predicate reads **ground truth**, not REView's
  own delivery bookkeeping: a roxyd whose trust tree diverged from REView's
  record (restored from an older backup, partially reset) reports its true
  below-target `epoch` and is caught up / flagged, rather than being silently
  counted "confirmed" while holding a retired key (RFC-D2 §4a, RFC-B §9). An
  agent that omits the field (pre-trust-reporting) decodes to "unknown epoch",
  which REView treats as un-confirmed, not confirmed-at-target.
  **This field is the CONNECT-time reading only.** It is exchanged once per
  connection, so it cannot report an activation that happens later on a
  still-open connection; the per-apply `TrustActive { active_epoch }` /
  `StaleTrustSet` ACK (§4) carries that. The two together give REView a
  reading at connect and a reading after every trust apply — which is what
  makes the ground-truth predicate usable on long-lived connections rather
  than only across reconnects (RFC-D2 §4a).
  **Reported epochs bound the agent's status DOWNWARD only.** The value is
  agent-asserted, so REView clamps it to its own active `epoch`: a report at
  or below it may mark the host caught-up, while a report **above** it is
  treated as un-confirmed and flagged, never as confirmed. Otherwise an agent
  could assert a high epoch, never be sent the chain, and display healthy while
  holding a revoked key — turning "read ground truth from the agent" into a
  bypass in the one direction an attacker wants (RFC-D2 §4a, RFC-B §9).
