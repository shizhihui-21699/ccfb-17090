# depaudit

Review tool for changes to Gradle's dependency-verification metadata
(`gradle/verification-metadata.xml`).

The file records a hash and a set of trusted signing keys for every artifact a build downloads.
It is thousands of lines long and almost nobody reads its diffs — which is exactly why editing one
hash in it, inside a merge request that otherwise looks like a routine change, is an effective
supply-chain attack. This tool turns such a diff into a short list of decisions.

```
$ depaudit --base origin/main
── BLOCKING: values contradict an authoritative source ─────────────────
  ✗ org.apache.commons:commons-lang3:3.17.0 commons-lang3-3.17.0.jar sha1
    gradle/verification-metadata.xml:412  sha1 b17d2136f046…ee70 → 000000000000…0000
      · maven-central (canonical) publishes a DIFFERENT value b17d2136f046… for
        org.apache.commons:commons-lang3:3.17.0 commons-lang3-3.17.0.jar
      · the canonical repository's digest for this exact version differs from the value
        in the merge request
────────────────────────────────────────────────────────────────────────
  RESULT: BLOCK — do not merge until the items above are resolved.
```

## The two hard problems

**Routine upgrades legitimately touch hundreds of records.** Gradle writes components sorted by
coordinates, so bumping one dependency deletes a block near the top of the file and inserts one near
the bottom. A positional diff reports two enormous changes and buries the one line that matters.
`depaudit` keys everything by coordinates and by artifact name, so:

- a version bump is recognised as *one* correlated upgrade, not hundreds of unrelated edits;
- a hash that changes **without** the version changing is isolated as the anomaly it is — a
  released artifact's bytes are immutable, so there is no benign explanation for it;
- an `also-trust` value being added is reported, even though it silently widens which bytes are
  accepted without touching the primary hash;
- an unscoped `<trusted-key>` being added is blocking, because it can vouch for any artifact,
  including ones added by a later merge request.

On a generated fixture of 400 dependencies where 50 are bumped and one hash is edited, the tool
reports 50 upgrades and exactly one finding. (See `ScaleTest`.)

**Some artifacts cannot be checked publicly at all.** Entries that exist only in an internal
repository, or the same version legitimately built differently for different platforms, have no
canonical hash to compare against. `depaudit` does not pretend otherwise — it has a five-way
verdict instead of pass/fail, and which repositories it consults is fixed by the *reviewer's*
configuration, never by anything written in the file under review:

| Evidence | Verdict |
|---|---|
| Canonical repository publishes this value | `CONFIRMED_CANONICAL` |
| Canonical repository has this version with a **different** digest | `CONTRADICTED` (blocks) |
| Only a mirror publishes it | `CONFIRMED_MIRROR` (review) |
| Nothing public has these coordinates; an internal repository serves the value | `INTERNAL_ONLY` (review) |
| New digest disagrees with the internal repository that served the old one | `CONTRADICTED` (blocks) |
| Could not reach anything | `INCONCLUSIVE` (review) |

A canonical disagreement is decided *first*: a mirror that serves the same forged bytes is
downstream of whoever forged them, not independent evidence. A network failure is never reported as
a contradiction — failing to ask is not evidence.

## Usage

```
depaudit --old <previous.xml>  --new <current.xml> [options]
depaudit --new <current.xml>   --base <git-rev>    [options]   # read the old side from git
```

| Option | Meaning |
|---|---|
| `--repo id=url[@tier]` | Add a repository to consult. `tier` is `canonical`, `mirror`, `internal` or `untrusted`, optionally `@offline`. Repeatable. Default: Maven Central as canonical. |
| `--keyring <file>` | PGP keyring of keys you trust, for signature verification. Repeatable. A pinned key wins over a keyserver. |
| `--keyserver <host>` | Best-effort key lookup. Unauthenticated, so weak evidence — prefer `--keyring`. |
| `--offline` | Parse and diff only; no network calls. |
| `--json` | Machine-readable output. |
| `--fail-on-review` | Exit 1 when a change needs human judgement. |

Exit codes: `0` all accounted for · `1` review needed (with `--fail-on-review`) · `2` blocked ·
`3` tool could not complete. Exit 1 and 2 are kept distinct on purpose: a check that fails on every
routine bump gets removed from the pipeline, and a removed check catches nothing.

Typical CI wiring:

```sh
depaudit --base "origin/${CHANGE_TARGET}" --repo internal=https://nexus.corp/repo@internal
```

## What it checks

1. **Digests** against configured repositories' published checksum files (`.sha1`, `.sha256`).
2. **Signatures** — detached `.asc` verified with BouncyCastle against a keyring you control.
   A valid signature by an *untrusted* key is not a pass; the tool reports which key signed and
   leaves the trust decision explicit. Crucially, the signature only confirms a change if the
   **signed bytes hash to the value under review** — a genuine signature over the served artifact
   says nothing about a hash the merge request invented, so the two are checked together.
3. **Trust configuration** — added/removed/rescoped trusted keys, `ignored-keys`, the
   `verify-metadata` and `verify-signatures` toggles, embedded key material.
4. **`origin` attributes.** Gradle writes prose there (`"Generated by Gradle"`), never a URL. A
   value that starts looking like a URL or host is a fabricated provenance claim and blocks.

## What it does not do

Stated plainly, because a security tool that overstates itself is worse than none:

- **It cannot prove an internal-only artifact is untampered.** `INTERNAL_ONLY` means "consistent
  with what your internal repository serves", not "this is what the upstream project built". If an
  attacker can also write to the internal repository, nothing here will catch it. Pin and verify
  signatures there too.
- **A keyserver key is not an identity.** Keyservers are unauthenticated; anyone can publish a key
  with any user id. Fetching a key only shows the signature is internally consistent with it. Use
  `KeyringKeySource` with keys you obtained out of band for anything that matters.
- **It does not scan artifacts for malware.** It checks that the bytes are the ones an authority
  published, not that those bytes are safe.
- **Absence from a canonical repository is only a signal.** For artifacts published elsewhere by
  design, an upgrade will read `INCONCLUSIVE` rather than confirmed. Configure an internal
  repository so the tool can say `INTERNAL_ONLY` instead of guessing.
- **`--offline` proves nothing about values.** It reports shape and trust changes only.

## Design notes

- **Parsing is hardened** against XXE, entity expansion and external DTDs: these files arrive in
  pull requests, so their bytes are attacker-controlled. Streaming SAX, not DOM, both for
  ten-thousand-component files and to record exact line numbers for the report.
- **Unmodelled elements are reported, not dropped.** An element this tool does not understand is
  surfaced as a change, so a hand-injected one cannot hide by being unrecognised.
- **Repositories come from configuration, not from the file.** Nothing in a pull request can widen
  what is considered authoritative.
- **Cross-host redirects are refused** when fetching checksums, so a checksum is only ever accepted
  from the repository it was requested from.

## Building

Requires JDK 21.

```sh
gradle build          # compile + 108 tests
gradle installDist    # ./build/install/depaudit/bin/depaudit
```

Tests run offline and include handwritten GnuPG-signed fixtures plus the real published
`commons-lang3-3.17.0.jar` and its maintainer's key, so signature verification is exercised against
genuine data rather than a mock.

## Layout

```
io.depaudit
├── Main, AuditService, GitBaseReader   CLI, pipeline, --base support
├── model/      ArtifactRef, ArtifactEntry, ComponentEntry, TrustedKey, VerificationMetadata
├── parse/      hardened SAX parser + handler (line numbers, unknown-element capture)
├── diff/       MetadataDiffer — coordinate-keyed diff, upgrade correlation, severity
├── verify/     ArtifactVerifier (decision table), UpgradeVerifier, repositories, policy
│   └── pgp/    PgpSignatureVerifier (BouncyCastle), keyring and keyserver sources
└── report/     AuditResult, TextReportRenderer, JsonReportRenderer
```
