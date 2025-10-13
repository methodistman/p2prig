## Phase 1: Handshake and negotiation

Handshake is performed once per TCP connection before any job frames when required by policy.

- `CLIENT_HELLO` payload:
  - `ver` (be16): protocol version requested (>=1)
  - `caps` (be32): capability bitset requested by the client
    - bit0 = RANDOMX supported by client/expectation
  - `tlen` (be16): length of token (see Phase 2)
  - `token[tlen]` (bytes): optional auth token

- `SERVER_HELLO` payload:
  - `ver` (be16): negotiated protocol version (1 for this phase)
  - `caps` (be32): device capability bitset
    - bit0 = RANDOMX supported by device
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

## JOB_SUBMIT

Payload fields:
- `header[80]`          (bytes)  // block header (or equivalent prefix) in host format expected by hash
- `target[32]`          (bytes)  // difficulty target in big-endian 256-bit
- `nonce_start`         (be64)
- `nonce_count`         (be32)
- `job_id`              (be64, optional)
- `flags`               (u8, optional)
  - bit0 = 1 => RandomX job
  - If RandomX:
    - `rx_seed[32]`     (bytes)
    - `rx_height`       (be32)

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
