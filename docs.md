# Recipe Session Artifact Transfer — Closeout + E2E Usage Docs

Status: complete.

This crate/lane now provides a metadata-only recipe session contract flow for artifact/file-transfer planning.

It supports:

* real recipe catalog path exports
* stable manifest hash references
* proposal / acceptance / lock handshakes
* concrete indexed path binding against wildcard permissions
* sender egress path authorization
* receiver receipt ingress authorization
* helper methods for e2e preflight-style checks
* non-live lock receipts proving no transport, bytes, sockets, or runtime invocation occurred

Final validated state:

```text
recipe-session: 61 passed / 0 failed
recipes catalog_hardening: 20 passed / 0 failed
workspace: green
progress: {6/6} + e2e helpers green
```

## Core idea

The pattern is:

```text
real file_transfer recipe catalog
→ exported path manifest
→ deterministic recipe/path hash references
→ artifact-transfer session contract
→ proposal
→ acceptance
→ locked contract
→ concrete egress path binding
→ concrete ingress receipt binding
→ non-live receipt proof
```

This lets code ask:

```text
“Is this sender allowed to emit this exact recipe-backed field?”
“Is this receiver allowed to return this exact receipt field?”
```

without opening a socket, moving bytes, encrypting data, invoking NodePlan, or touching a live runtime.

## Main public surface

The primary closeout API is:

```rust
RecipeSessionArtifactTransferFixture::manifest_hashes(...)
RecipeSessionArtifactTransferFixture::locked_contract(...)
RecipeSessionArtifactTransferFixture::can_emit_path(...)
RecipeSessionArtifactTransferFixture::can_receive_receipt_path(...)
RecipeSessionArtifactTransferFixture::declared_permission_direction(...)
```

The main types involved are:

```rust
RecipeSessionArtifactTransferFixture
RecipeSessionHash
RecipeSessionContract
RecipeSessionProposal
RecipeSessionParticipant
RecipeSessionRole
RecipeSessionRecipeRef
RecipeSessionPathPermission
RecipeSessionReceiptPolicy
RecipeSessionSecurityPolicy
LockedRecipeSessionContract
RecipeSessionDirection
RecipeSessionError
```

## Full happy-path usage

```rust
use recipe_session::{
RecipeSessionArtifactTransferFixture,
RecipeSessionHash,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
// 1. Pull the real file-transfer pathgen export.
let export = recipes::file_transfer::uneven_multi_file_pathgen_export();


// 2. Build stable fixture hashes from the real path manifest material.
let (recipe_manifest_hash, path_manifest_hash) =
    RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

// 3. Build, accept, and lock the metadata-only artifact-transfer session.
let locked = RecipeSessionArtifactTransferFixture::locked_contract(
    "artifact-proposal-1",
    "artifact-acceptance-1",
    "artifact-lock-1",
    "artifact-contract-1",
    "artifact-sender",
    "artifact-receiver",
    recipe_manifest_hash,
    path_manifest_hash,
)?;

// 4. Authorize a concrete egress path.
let payload_len_binding = locked.locked_contract().bind_egress_path(
    "file_transfer.multi_file_then_instruction.packets[4].payload_len",
)?;

assert_eq!(
    payload_len_binding.matched_permission().path().as_str(),
    "file_transfer.multi_file_then_instruction.packets[*].payload_len",
);

// 5. Authorize a concrete ingress receipt path.
let receipt_status_binding = locked
    .locked_contract()
    .bind_ingress_path("receipts[0].status")?;

assert_eq!(
    receipt_status_binding.matched_permission().path().as_str(),
    "receipts[*].status",
);

// 6. Produce a non-live lock receipt.
let receipt = locked.receipt("artifact-lock-receipt-1")?;

assert!(!receipt.no_live_evidence().live_transport_used());
assert_eq!(receipt.no_live_evidence().bytes_sent(), 0);
assert_eq!(receipt.no_live_evidence().bytes_received(), 0);

Ok(())

}
```

## One-call lock helper

Use this when the caller does not need to manually expose proposal and acceptance steps.

```rust
let export = recipes::file_transfer::uneven_multi_file_pathgen_export();

let (recipe_hash, path_hash) =
RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

let locked = RecipeSessionArtifactTransferFixture::locked_contract(
"artifact-proposal-1",
"artifact-acceptance-1",
"artifact-lock-1",
"artifact-contract-1",
"artifact-sender",
"artifact-receiver",
recipe_hash,
path_hash,
)?;
```

This performs:

```text
contract construction
→ proposal
→ acceptance
→ lock
```

but remains metadata-only.

## Manual handshake flow

Use this when the product wants to show or persist the handshake steps separately.

```rust
let export = recipes::file_transfer::uneven_multi_file_pathgen_export();

let (recipe_hash, path_hash) =
RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

let proposal = RecipeSessionArtifactTransferFixture::proposal(
"artifact-proposal-1",
"artifact-contract-1",
"artifact-sender",
"artifact-receiver",
recipe_hash,
path_hash,
)?;

let acceptance = proposal.accept(
"artifact-acceptance-1",
"artifact-receiver",
proposal.contract().clone(),
)?;

let locked = proposal.lock("artifact-lock-1", &acceptance)?;
```

This exposes the handshake as explicit stages.

## Helper-based preflight checks

The helper methods let callers ask whether a path is authorized without needing to care about the binding result shape.

```rust
let can_emit_payload_len = RecipeSessionArtifactTransferFixture::can_emit_path(
&locked,
"file_transfer.multi_file_then_instruction.packets[4].payload_len",
);

let can_receive_status = RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
&locked,
"receipts[0].status",
);

assert!(can_emit_payload_len);
assert!(can_receive_status);
```

This is useful for adapter preflight, tests, UI inspection, or later runtime planning.

## Egress item paths

The fixture authorizes item-level transfer metadata:

```text
file_transfer.multi_file_then_instruction.items[*].name
file_transfer.multi_file_then_instruction.items[*].declared_len
file_transfer.multi_file_then_instruction.items[*].chunk_recipe_name
file_transfer.multi_file_then_instruction.items[*].start_seq
file_transfer.multi_file_then_instruction.items[*].packet_start
file_transfer.multi_file_then_instruction.items[*].packet_end_exclusive
file_transfer.multi_file_then_instruction.items[*].end_seq
file_transfer.multi_file_then_instruction.items[*].packet_count
```

Example:

```rust
let declared_len = locked.locked_contract().bind_egress_path(
"file_transfer.multi_file_then_instruction.items[0].declared_len",
)?;

assert_eq!(
declared_len.matched_permission().path().as_str(),
"file_transfer.multi_file_then_instruction.items[*].declared_len",
);

let packet_count = locked.locked_contract().bind_egress_path(
"file_transfer.multi_file_then_instruction.items[1].packet_count",
)?;

assert_eq!(
packet_count.matched_permission().path().as_str(),
"file_transfer.multi_file_then_instruction.items[*].packet_count",
);
```

## Egress packet paths

The fixture authorizes packet-level transfer metadata:

```text
file_transfer.multi_file_then_instruction.packets[*].item_name
file_transfer.multi_file_then_instruction.packets[*].chunk_recipe_name
file_transfer.multi_file_then_instruction.packets[*].seq
file_transfer.multi_file_then_instruction.packets[*].item_byte_start
file_transfer.multi_file_then_instruction.packets[*].item_byte_end
file_transfer.multi_file_then_instruction.packets[*].payload_len
file_transfer.multi_file_then_instruction.packets[*].is_final_for_item
file_transfer.multi_file_then_instruction.next_instruction_seq
```

Example:

```rust
let packet_seq = locked.locked_contract().bind_egress_path(
"file_transfer.multi_file_then_instruction.packets[4].seq",
)?;

assert_eq!(
packet_seq.matched_permission().path().as_str(),
"file_transfer.multi_file_then_instruction.packets[*].seq",
);

let payload_len = locked.locked_contract().bind_egress_path(
"file_transfer.multi_file_then_instruction.packets[4].payload_len",
)?;

assert_eq!(
payload_len.matched_permission().path().as_str(),
"file_transfer.multi_file_then_instruction.packets[*].payload_len",
);

let is_final = locked.locked_contract().bind_egress_path(
"file_transfer.multi_file_then_instruction.packets[5].is_final_for_item",
)?;

assert_eq!(
is_final.matched_permission().path().as_str(),
"file_transfer.multi_file_then_instruction.packets[*].is_final_for_item",
);
```

## Ingress receipt paths

Receipt paths are intentionally session metadata, not file-transfer recipe value paths.

```text
receipts[*].packet_seq
receipts[*].status
receipts[*].digest
```

Example:

```rust
let packet_seq = locked
.locked_contract()
.bind_ingress_path("receipts[0].packet_seq")?;

assert_eq!(
packet_seq.matched_permission().path().as_str(),
"receipts[*].packet_seq",
);

let status = locked
.locked_contract()
.bind_ingress_path("receipts[0].status")?;

assert_eq!(
status.matched_permission().path().as_str(),
"receipts[*].status",
);

let digest = locked
.locked_contract()
.bind_ingress_path("receipts[0].digest")?;

assert_eq!(
digest.matched_permission().path().as_str(),
"receipts[*].digest",
);
```

## Direction classification

Declared permission paths can be classified by fixture direction.

```rust
assert_eq!(
RecipeSessionArtifactTransferFixture::declared_permission_direction(
"file_transfer.multi_file_then_instruction.packets[*].payload_len",
),
Some(RecipeSessionDirection::Egress),
);

assert_eq!(
RecipeSessionArtifactTransferFixture::declared_permission_direction(
"receipts[*].status",
),
Some(RecipeSessionDirection::Ingress),
);

assert_eq!(
RecipeSessionArtifactTransferFixture::declared_permission_direction(
"file_transfer.multi_file_then_instruction.packets[*].payload_digest",
),
None,
);
```

Important: this classifies declared fixture permission patterns. It is not meant to classify every arbitrary concrete indexed path. For concrete runtime paths, use binding or the can_emit/can_receive helpers.

## Rejection: unknown sibling path

The fixture rejects fields that were not declared.

```rust
let forbidden = locked.locked_contract().bind_egress_path(
"file_transfer.multi_file_then_instruction.packets[0].payload_digest",
);

assert!(matches!(
forbidden,
Err(RecipeSessionError::PathAccessDenied { direction, path })
if direction == RecipeSessionDirection::Egress
&& path == "file_transfer.multi_file_then_instruction.packets[0].payload_digest"
));
```

Helper version:

```rust
assert!(!RecipeSessionArtifactTransferFixture::can_emit_path(
&locked,
"file_transfer.multi_file_then_instruction.packets[0].payload_digest",
));
```

## Rejection: wrong direction

Receipt paths are ingress-only.

```rust
let wrong_direction = locked
.locked_contract()
.bind_egress_path("receipts[0].status");

assert!(matches!(
wrong_direction,
Err(RecipeSessionError::PathAccessDenied { direction, path })
if direction == RecipeSessionDirection::Egress
&& path == "receipts[0].status"
));
```

Helper version:

```rust
assert!(!RecipeSessionArtifactTransferFixture::can_emit_path(
&locked,
"receipts[0].status",
));

assert!(!RecipeSessionArtifactTransferFixture::can_receive_receipt_path(
&locked,
"file_transfer.multi_file_then_instruction.packets[0].payload_len",
));
```

## Connect real recipe values to session permissions

This proves the authorized path is both contract-valid and resolvable against the real recipe fixture value.

```rust
let locked = /* locked artifact fixture contract */;

let schedule = recipes::file_transfer::uneven_multi_file_fixture();
let export = schedule.to_pathgen_export("file_transfer");
let value = schedule.to_value();

let concrete = "file_transfer.multi_file_then_instruction.packets[4].payload_len";

assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
&locked,
concrete,
));

let wildcard = recipe_writer::path_lookup::wildcardize_indexes(concrete);

assert_eq!(
wildcard,
"file_transfer.multi_file_then_instruction.packets[*].payload_len",
);

assert!(export.contains_path(&wildcard));

let relative = RecipeSessionArtifactTransferFixture::relative_value_path(concrete)
.expect("file-transfer egress path should map to recipe_writer value path");

let found = recipe_writer::path_lookup::lookup_value_path(&value, relative)?;

println!("packet[4].payload_len = {found:?}");
```

## Collect packet lengths for future send attempts

This is the bridge toward a later non-live send-attempt planner.

```rust
let locked = /* locked artifact fixture contract */;

let schedule = recipes::file_transfer::uneven_multi_file_fixture();
let value = schedule.to_value();

assert!(RecipeSessionArtifactTransferFixture::can_emit_path(
&locked,
"file_transfer.multi_file_then_instruction.packets[0].payload_len",
));

let relative_payload_lens =
RecipeSessionArtifactTransferFixture::relative_value_path(
"file_transfer.multi_file_then_instruction.packets[*].payload_len",
)
.unwrap();

let payload_lens =
recipe_writer::path_lookup::collect_value_path(&value, relative_payload_lens)?;

assert_eq!(payload_lens.len(), 6);

for payload_len in payload_lens {
println!("packet payload_len = {payload_len:?}");
}
```

This supports the future pattern:

```text
recipe fixture schedule
→ packet metadata list
→ contract-authorized packet fields
→ future send-attempt material
```

## Manual flow and one-call flow agree

The e2e helper tests prove that manual and one-call flows authorize the same paths.

```rust
let export = recipes::file_transfer::uneven_multi_file_pathgen_export();

let (recipe_hash, path_hash) =
RecipeSessionArtifactTransferFixture::manifest_hashes(&export.to_manifest_lines());

let manual_proposal = RecipeSessionArtifactTransferFixture::proposal(
"manual-proposal-1",
"manual-contract-1",
"artifact-sender",
"artifact-receiver",
recipe_hash.clone(),
path_hash.clone(),
)?;

let manual_acceptance = manual_proposal.accept(
"manual-acceptance-1",
"artifact-receiver",
manual_proposal.contract().clone(),
)?;

let manual_locked = manual_proposal.lock(
"manual-lock-1",
&manual_acceptance,
)?;

let one_call_locked = RecipeSessionArtifactTransferFixture::locked_contract(
"one-call-proposal-1",
"one-call-acceptance-1",
"one-call-lock-1",
"one-call-contract-1",
"artifact-sender",
"artifact-receiver",
recipe_hash,
path_hash,
)?;

let path = "file_transfer.multi_file_then_instruction.packets[4].payload_len";

assert_eq!(
RecipeSessionArtifactTransferFixture::can_emit_path(&manual_locked, path),
RecipeSessionArtifactTransferFixture::can_emit_path(&one_call_locked, path),
);
```

## Non-live receipt proof

The locked session can produce a receipt proving the lock happened without live runtime effects.

```rust
let receipt = locked.receipt("artifact-lock-receipt-1")?;

assert!(!receipt.no_live_evidence().live_transport_used());
assert_eq!(receipt.no_live_evidence().bytes_sent(), 0);
assert_eq!(receipt.no_live_evidence().bytes_received(), 0);
```

This is important because this crate is still contract/metadata only.

## What this does not do

This lane intentionally does not include:

```text
NodePlan integration
live sockets
live transport
byte movement
encryption implementation
runtime invocation
remote acknowledgement polling
storage writes
packet delivery
network confirmation
```

Those are later layers.

## What should come next

The next layer should probably be outside `recipe-session`.

A good next crate/pass would be:

```text
recipe_session_transfer_plan_adapter_pass
```

Its job would be to consume:

```text
LockedRecipeSessionContract

* recipes::file_transfer schedule/value
* authorized fixture paths
  ```

and produce metadata-only send-attempt planning material, such as:

```text
packet index
packet seq
item name
item byte range
payload length
is final for item
authorized egress binding material
expected receipt ingress paths
non-live planning receipt
```

Still no live transport.

The next pattern should be:

```text
locked recipe session
→ file_transfer schedule values
→ authorized packet send-attempt descriptors
→ expected receipt descriptors
→ non-live adapter planning receipt
```

This would be the correct bridge toward runtime/adapters without jumping straight into sockets or NodePlan.

## Validation command

Run this after edits to verify the current lane:

```bash
cargo fmt --all
cargo test -p recipe-session --all-features
cargo test -p recipes --test catalog_hardening --all-features
cargo test --workspace --all-targets
```

Expected signal:

```text
recipe-session: 61 passed / 0 failed
recipes catalog_hardening: 20 passed / 0 failed
workspace: green
```

## Final summary

The completed `recipe-session` lane now gives a clean standalone contract layer:

```text
A recipe-backed producer and consumer can agree to a specific artifact-transfer session,
lock that agreement,
bind concrete runtime paths against wildcard recipe permissions,
authorize receiver receipt metadata,
and prove the whole handshake remained metadata-only.
```

That is the right stopping point for this crate.

The next meaningful work is an adapter/planner layer that consumes the locked session and creates non-live packet/send-attempt descriptors.
