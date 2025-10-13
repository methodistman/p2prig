# Contributing

Thanks for your interest in contributing to p2prig!

## How to propose changes

- Fork the repository and create a topic branch from `main`.
- Keep PRs focused and reasonably small; one logical change per PR.
- Include a clear description of motivation, approach, and testing.

## Coding guidelines

- C (device-daemon)
  - Prefer portable C11, avoid global state unless guarded by locks.
  - Use `__asm__ __volatile__` for inline assembly; guard by `#if defined(__aarch64__)`/`#if defined(__x86_64__)`.
  - Serialize writes across threads using per-connection mutexes.
- C++ (xmrig)
  - Follow existing XMRig style where possible; do not introduce RTTI.
  - Keep remote backend scoped under `src/backend/remote/`.

## Testing

- Unit and integration tests are welcome where practical.
- For RandomX performance testing, enable huge pages and MSR where applicable.

## Signing and DCO

- Include a `Signed-off-by: Your Name <email>` line in your commit message if you are contributing under a Developer Certificate of Origin (optional, recommended for larger contributions).

## Security

- Avoid introducing network-facing vulnerabilities in the binary protocol parser.
- Treat untrusted inputs defensively: check lengths and bounds, avoid integer overflows, validate opcodes.

## License

- `xmrig/` is GPLv3; contributions to this directory are under GPLv3.
- `device-daemon/` license is pending; contributions will be relicensed once the project owner specifies the license.
