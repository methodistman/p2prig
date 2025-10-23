# XMRig

[![Github All Releases](https://img.shields.io/github/downloads/xmrig/xmrig/total.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub release](https://img.shields.io/github/release/xmrig/xmrig/all.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub license](https://img.shields.io/github/license/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/network)

XMRig is a high performance, open source, cross platform RandomX, KawPow, CryptoNight and [GhostRider](https://github.com/xmrig/xmrig/tree/master/src/crypto/ghostrider#readme) unified CPU/GPU miner and [RandomX benchmark](https://xmrig.com/benchmark). Official binaries are available for Windows, Linux, macOS and FreeBSD.

## Mining backends
- **CPU** (x86/x64/ARMv7/ARMv8)
- **OpenCL** for AMD GPUs.
- **CUDA** for NVIDIA GPUs via external [CUDA plugin](https://github.com/xmrig/xmrig-cuda).

## Download
* **[Binary releases](https://github.com/xmrig/xmrig/releases)**
* **[Build from source](https://xmrig.com/docs/miner/build)**

## Usage
The preferred way to configure the miner is the [JSON config file](https://xmrig.com/docs/miner/config) as it is more flexible and human friendly. The [command line interface](https://xmrig.com/docs/miner/command-line-options) does not cover all features, such as mining profiles for different algorithms. Important options can be changed during runtime without miner restart by editing the config file or executing [API](https://xmrig.com/docs/miner/api) calls.

* **[Wizard](https://xmrig.com/wizard)** helps you create initial configuration for the miner.
* **[Workers](http://workers.xmrig.info)** helps manage your miners via HTTP API.

## Donations
* Default donation 1% (1 minute in 100 minutes) can be increased via option `donate-level` or disabled in source code.
* XMR: `48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD`

## Developers
* **[xmrig](https://github.com/xmrig)**
* **[sech1](https://github.com/SChernykh)**

## Contacts
* support@xmrig.com
* [reddit](https://www.reddit.com/user/XMRig/)
* [twitter](https://twitter.com/xmrig_dev)


## PeerServer and Remote Backend (Experimental)

This fork embeds an experimental Peer-to-Peer module to delegate RandomX work to local or remote peers from inside XMRig.

- **PeerServer**: a lightweight libuv TCP server inside XMRig that accepts delegated work frames and executes them using RandomX.
- **RemoteBackend**: an experimental backend that connects to one or more PeerServers and submits work slices.

### Build

Enable the features at configure time:

```bash
cmake -S . -B build \
  -DWITH_PEER=ON \
  -DWITH_REMOTE=ON \
  -DWITH_BENCHMARK=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

### Configuration

Add the `peer` section to your JSON config to run the embedded server:

```json
{
  "peer": {
    "enabled": true,
    "bind": "127.0.0.1",
    "port": 9000
  }
}
```

Example minimal files in this repo:

- `config.peer.json` – enables the PeerServer and HTTP API for inspection.
- `config.remote.json` – standard miner config used for remote/bench examples.
- `config.loopback.json` – minimal bench config to drive local validation with `-a rx`.

### RemoteBackend (env-driven)

The RemoteBackend is enabled by environment variables and starts automatically when present:

- `P2PRIG_ENDPOINTS` – comma-separated endpoints: `host:port[:weight]` (e.g. `127.0.0.1:9000`, `10.0.0.2:9001:2`).
- `P2PRIG_BATCH` – initial batch size (nonces per slice), default ~1,048,576.
- `P2PRIG_TUNE_TARGET_MS` – target slice duration in ms for auto-tuning (default 800).
- `P2PRIG_TUNE_STEP_PCT` – batch adjustment step percent (default 10).

Start any normal XMRig run and set the variables, for example:

```bash
P2PRIG_ENDPOINTS=127.0.0.1:9000 \
P2PRIG_BATCH=200000 \
./xmrig -a rx -o stratum+ssl://rx.unmineable.com:443 \
  -u BTT:TT5sFMQRKKb34DLht8L57sYtrebrcipBzv.unmineable_worker_dikyct \
  -p x --http-host=127.0.0.1 --http-port=8082
```

### Loopback validation (bench-driven)

1) Start the PeerServer:

```bash
./xmrig -c ./config.peer.json
```

2) Start a local client that connects back to the peer and drives small RandomX benchmarks:

```bash
P2PRIG_ENDPOINTS=127.0.0.1:9000 \
P2PRIG_BATCH=100000 \
./xmrig -a rx --bench=200K -c ./config.loopback.json --http-host=127.0.0.1 --http-port=8082
```

### HTTP API additions

The miner summary (`GET /2/summary`) includes a new `peer_server` object:

```json
"peer_server": {
  "enabled": true,
  "bind": "127.0.0.1",
  "port": 9000,
  "connections": 0
}
```

Remote backend details appear in `GET /2/backends` under `type: "remote"`, including connection status, per-remote metadata, and batch sizing. When `P2PRIG_*` variables are not set, the remote backend remains disabled.

### Notes

- RandomX huge pages (including 1 GB if available) significantly improve performance.
- The PeerServer reports a running connection counter; it may represent total accepts rather than current live connections depending on your version.
- The protocol is evolving; current implementation supports handshake, `JOB_SUBMIT` (XJ), slice lease (XL), `RESULT`, `DONE`, `SLICE_DONE_EXT`, and `JOB_ABORT`.

## CLI UI (Terminal)

This repository includes a simple Bash-based terminal UI to monitor the miner and peer status using the built-in HTTP API.

- Script: `tools/peer_ui.sh`
- Requirements: `bash`, `curl`, `python3`, `ss` (iproute2)

Usage:

```bash
./tools/peer_ui.sh -p 8082 --peer-port 8080
./tools/peer_ui.sh -p 8082 --watch 2
```

Displayed fields:

- Processors (CPU thread table)
- Token and full user being mined (parsed from `-u` argument)
- Hashrate (10s, 60s) and Total hashrate
- Estimated RandomX dataset size, RAM free/total
- Peer server status (enabled/bind/port/connections)
- Remote backend status and connected remotes (when enabled via env)
