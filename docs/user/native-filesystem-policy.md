# Experimental native filesystem policy

This experiment adds Dogwood checks to selected native file operations on macOS.
It requires macOS 27 or later and a binary built with the macOS 27 SDK or later.
The binary must carry Apple's Endpoint Security entitlement and a valid signature.
Endpoint Security is the macOS interface that lets a client decide selected operating system requests.

## Enable the experiment

Build the product and its helpers:

```sh
cargo build --release --locked -p strands-box -p strands-box-containment --features native-filesystem-policy
```

Sign the product bundle with an identity and provisioning profile that permit `com.apple.developer.endpoint-security.client`.
Add this table to `box.toml`:

```toml
[experimental-features]
native-filesystem-policy = true
```

Run the signed product with `run --config /absolute/path/box.toml`.
An absent table or `false` leaves native interception disabled, including in an `--all-features` build.
A selected but unavailable mechanism refuses startup. Box never silently disables the selected checks.
Standard release artifacts exclude the experiment.

## Coverage and limits

The adapter checks open, create, unlink, rename, and truncate requests from descendants of the trusted Box process.
It uses the box's existing durable Dogwood history. Filesystem grants still restrict each process through Seatbelt, the macOS process sandbox.
A policy permit cannot expand those grants.

The adapter disables authorization caching and requests kernel denial for missed deadlines or dropped authorization messages.
Accepted authorization replies produce `indeterminate` outcomes. These records confirm authorization, not successful filesystem effects.

An existing open file descriptor can still carry later reads or writes without another open request.
This experiment does not revoke existing descriptors or intercept every filesystem operation.
Shutdown terminates tracked descendants, including detached children, before interception stops.
It uses a five-second deadline for descendant cleanup and callback draining.
Startup checks subscriptions and removes path mutes that would suppress required events.
It refuses startup if required events remain muted or any process mute exists.

The signed tests cover detached-child cleanup and durable history across mode changes.
They do not establish enforcement after the trusted Box process crashes or validate every shutdown failure.
Production use still requires further review and tests for those failures.

## Stored configuration and rollback

Disabled configurations retain record version 21. Enabled configurations use version 22.
Older binaries refuse version 22 rather than silently losing enforcement.
To disable the experiment, change the setting to `false`.
Run once with the native-capable build before returning to an older binary.
This writes a version 21 record while retaining durable policy history.
Changing the setting directly to `false` does not authorize an older binary to parse an existing version 22 record.

## Validate a signed build

Use the separate native test package after building and signing the current source:

```sh
STRANDS_BOX_SIGNED_TEST_BINARY=/absolute/path/KernelBox.app/Contents/MacOS/strands-box \
  cargo test --manifest-path test-native-filesystem/Cargo.toml --locked -- --nocapture
```

Record the source revision, source changes, and signed executable hash beside the test output.
The test package requires the binary path and bounds each workload to 60 seconds.
Ordinary workspace tests do not need a signing identity.
