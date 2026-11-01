# MODEL PERFORMANCE AND HARDWARE BENCHMARK REPORT

**Project:** Hybrid AI Prompt Injection Detection and Defense Platform  
**Audit Timestamp:** 2026-10-30 23:03:34  

---

## 1. Test Hardware & Execution Environment

| Component | Specification |
| :--- | :--- |
| **Operating System** | `Windows-10-10.0.26300-SP0` |
| **CPU Architecture** | `AMD64 Family 25 Model 68 Stepping 1, AuthenticAMD` (8 Physical Cores / 16 Logical Threads) |
| **System Memory (RAM)** | `31.31 GB` |
| **Dedicated GPU** | `NVIDIA GeForce RTX 4050 Laptop GPU` |
| **GPU VRAM** | `6.0 GB GDDR6` |
| **CUDA Version** | `12.1` |
| **PyTorch Runtime** | `2.5.1+cu121` |

---

## 2. Latency Benchmarks (Hybrid Pipeline & Layer 3)

| Benchmark Scenario | Sample Size | Mean Latency | Median (P50) | P90 | P95 | P99 | Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cold Startup Request** | 1 | `13.22 ms` | `13.22 ms` | - | - | - | - |
| **Full Pipeline Warm (Short)** | 50 | `10.37 ms` | `10.08 ms` | `11.29 ms` | `12.35 ms` | `15.52 ms` | `96.4 req/s` |
| **Transformer-Only CPU** | 20 | `16.89 ms` | `14.74 ms` | - | - | - | `59.2 req/s` |
| **Transformer-Only GPU** | 30 | `5.19 ms` | `5.19 ms` | - | - | - | `192.7 req/s` |

---

## 3. Memory & Resource Consumption

* **Current Process RSS:** `1495.46 MB`
* **GPU Memory Allocated:** `265.6 MB`
* **GPU Memory Reserved:** `960.0 MB`
* **Resource Stability:** Zero memory growth detected across continuous repeated inference passes.
