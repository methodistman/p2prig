## Lease/ACK Slice Protocol (XL)

Enabled when both sides advertise `caps.bit1` in `CLIENT_HELLO`/`SERVER_HELLO`.

### SLICE_LEASE_REQ (XL)

Payload prefixed by ASCII `'X','L'` and version `u8`:

- `slice_id`    (be64)   // chosen by host, unique per connection
- `job_id`      (be64)
- `flags`       (u8)
- `nonce_size`  (u8)
- `nonce_off`   (be32)
- `blob_len`    (be32)
- `blob[blob_len]`
- `nonce_start` (be64)
- `nonce_count` (be32)
- `target32`    (32 bytes)
- `target64`    (be64)
- If `flags&1` (RandomX):
  - `rx_seed[32]`
  - `rx_height` (be32)

Notes:
- This is a slice-based lease for a portion of nonce space of the given `job_id`.
- Host must ensure nonce-space monotonicity across leases to prevent overlaps.

### SLICE_ACK

Payload:

- `slice_id`     (be64)
- `accepted`     (u8)   // 1=accepted, 0=rejected
- `reason`       (u8)   // reason code for rejection (0=none)
- `start_ts_ms`  (be64) // device clock, milliseconds since epoch

### SLICE_DONE_EXT

Payload:

- `slice_id`     (be64)
- `job_id`       (be64)
- `processed`    (be64) // number of nonces actually processed
- `duration_ms`  (be64) // wall clock elapsed for this slice on device
- `shares_found` (be32) // number of RESULT frames emitted during slice

Notes:
- Devices must still emit `RESULT` frames during processing.
- When lease mode is active, `DONE` may be omitted for that job; `SLICE_DONE_EXT` serves as the finalization for each slice.

### Timing and autotune (host guidance)

- Hosts can compute slice duration using `duration_ms` (or arrival delta) and apply EWMA to adjust `nonce_count` for target duration.
- Suggested target slice duration: 0.8–1.2 seconds; adjust via environment (e.g., `P2PRIG_TUNE_TARGET_MS`).
- Respect `META_RESP.max_batch` and device capability limits when increasing batch.

## Phase 1: Handshake and negotiation

Handshake is performed once per TCP connection before any job frames when required by policy.

- `CLIENT_HELLO` payload:
  - `ver` (be16): protocol version requested (>=1)
  - `caps` (be32): capability bitset requested by the client
    - bit0 = RANDOMX supported by client/expectation
    - bit1 = LEASE/ACK slices supported by client
  - `tlen` (be16): length of token (see Phase 2)
  - `token[tlen]` (bytes): optional auth token

- `SERVER_HELLO` payload:
  - `ver` (be16): negotiated protocol version (1 for this phase)
  - `caps` (be32): device capability bitset
    - bit0 = RANDOMX supported by device
    - bit1 = LEASE/ACK slices supported by device
  - `auth_required` (u8): whether this device requires authentication

Clients should tolerate unknown tail fields (forward compatible). If handshake is not required, legacy flows MAY proceed directly to `META_RESP` and job frames.

## Phase 1: ERROR frame

`ERROR` payload:
- `code` (be16): semantic error code
- `msg_len` (be16): length of message
- `msg[msg_len]` (bytes): UTF-8 error string (optional)

Suggested codes:
- `0x0001` version_unsupported
- `0x0002` auth_required
- `0x0003` unauthorized
- `0x0004` malformed

Devices should send `ERROR` and close on fatal negotiation failures. Unknown fields must be tolerated.

# P2P Mining Protocol (Binary Frames)

Length-prefixed binary framing over TCP/TLS. All multi-byte integers are big-endian unless stated otherwise.

- Frame = LenBE(8) || Opcode(1) || Payload(Len-1)
- LenBE is total bytes including the opcode and payload.

## Opcodes

- 0x01 `META_REQ`  (Host→Device)
- 0x02 `META_RESP` (Device→Host)
- 0x10 `JOB_SUBMIT` (Host→Device)
- 0x11 `JOB_ABORT`  (Host→Device)
- 0x12 `RESULT`     (Device→Host)
- 0x13 `DONE`       (Device→Host)
- 0x40 `SLICE_LEASE_REQ` (Host→Device)
- 0x41 `SLICE_ACK`       (Device→Host)
- 0x43 `SLICE_DONE_EXT`  (Device→Host)
- 0x20 `PING`       (Either side)
- 0x21 `PONG`       (Either side)
 - 0x30 `CLIENT_HELLO` (Host→Device) [Phase 1]
 - 0x31 `SERVER_HELLO` (Device→Host) [Phase 1]
 - 0x7F `ERROR`        (Either side) [Phase 1]

## META_RESP

JSON UTF-8 body in payload:
```json
{"cpu_count": <int>, "max_batch": <int>}
```
- `cpu_count`: number of worker threads the device prefers to run.
- `max_batch`: suggested maximum nonce batch per job for this device.

## JOB_SUBMIT (XJ extended format)

Payload uses a compact, versioned binary envelope prefixed by ASCII `'X','J'` and version `u8`. Fields below are in the payload after the 3-byte prefix:

- `job_id`      (be64)
- `flags`       (u8)
  - bit0 = 1 => RandomX
- `nonce_size`  (u8)  // 4 or 8 bytes written into blob at `nonce_off`
- `nonce_off`   (be32)
- `blob_len`    (be32)
- `blob[blob_len]` (bytes) // algorithm-specific input; if 0, device hashes `header[80]`
- `nonce_start` (be64)
- `nonce_count` (be32)
- `target32`    (32 bytes) // big-endian 256-bit
- `target64`    (be64)     // compact 64-bit target for fast compare
- If `flags&1` (RandomX):
  - `rx_seed[32]` (bytes)
  - `rx_height`   (be32)

Notes:
- If `job_id` is omitted, device may assign a random id and use it in responses.
- If `flags` omitted, treated as 0.

## JOB_ABORT

Payload:
- `job_id` (be64)

Marks the in-flight job as canceled. Device should stop processing asap and not send further `RESULT` for that job. It still sends a final `DONE` with the processed counter so the host can reclaim remaining nonce range.

## RESULT

Payload:
- `job_id` (be64)
- `nonce`  (be64)
- `hash[32]` (bytes) // raw 32-byte hash

Emitted each time a nonce meets the target. Host validates and submits the share upstream.

## DONE

Payload:
- `job_id`    (be64)
- `processed` (be64)

Sent when the device finishes (or aborts) the job, indicating how many nonces were actually processed.

## PING/PONG

Keepalive frames. Either endpoint may send `PING`; the peer should reply with `PONG`.

## Concurrency and ordering

- Writes must be serialized per connection to avoid interleaving frames from multiple worker threads.
- Multiple worker threads can process the same job or different jobs concurrently; the device must ensure `RESULT`/`DONE` frames are atomically written.

## RandomX specifics

- Input: `header || nonce_be64` (device composes this internally).
- Target compare: treat `hash` as little-endian 256-bit; convert to big-endian u64 limbs and compare lexicographically to `target`.
- Cache (seed) is selected by `rx_seed` (and optionally `rx_height`).
