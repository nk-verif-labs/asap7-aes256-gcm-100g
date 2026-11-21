# asap7-aes256-gcm-100g

**128 Gbps 14-Stage Pipelined AES-256-GCM (CTR + GHASH) Line-Rate Crypto Engine** targeting **ASAP7 (7 nm FinFET predictive PDK)** @ **1.0 GHz (`1000 ps`)**.

## Architecture Overview
- **Top Module:** `aes256_gcm_top`
- **Datapath:** `128-bit` AXI4-Stream @ `1.0 GHz` = **`128 Gbps`** peak internal authenticated encryption rate.
- **NIST Standards:** FIPS-197 (AES-256 14-round pipeline + 60-word key expansion) & SP 800-38D (GF($2^{128}$) GHASH authentication tag).

## Quick Start
```bash
source ~/.venvs/cocotb19/bin/activate
make -C tb SIM=icarus && make -C tb SIM=verilator
```

## Release Roadmap
- `v1.0.0` (Nov 21, 2026): 14-stage AES-256-GCM RTL, NIST Cocotb verification, ASAP7 7 nm ORFS GDSII
- `v1.1.0` (Nov 28, 2026): Multi-$V_T$ PPA tuning + post-route Gate-Level Simulation (GLS) in CI
