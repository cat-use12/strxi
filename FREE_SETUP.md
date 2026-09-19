# Strix — Setup Gratis Tanpa API Key Berbayar

Strix membutuhkan LLM (Large Language Model) sebagai "otak" agent-nya.
Berikut 3 cara mendapatkannya **100% gratis**.

---

## Opsi 1: Groq (PALING DIREKOMENDASIKAN — Gratis & Cepat)

Groq memberikan **API key gratis** dengan quota harian yang cukup untuk testing.

### Langkah:
1. Buka **https://console.groq.com** → Sign Up (gratis)
2. Klik **API Keys** → **Create API Key**
3. Copy API key-nya, lalu jalankan:

```bash
export GROQ_API_KEY="gsk_xxxxxxxxxxxxxxxxxxxx"
export STRIX_LLM="groq/llama-3.3-70b-versatile"

strix scan --target https://target-kamu.com
```

### Model Groq gratis terbaik untuk pentesting:
| Model | Cocok untuk |
|-------|-------------|
| `groq/llama-3.3-70b-versatile` | Scan mendalam, reasoning bagus |
| `groq/deepseek-r1-distill-llama-70b` | Analisis kode, bug logic |
| `groq/qwen-qwq-32b` | Multi-step reasoning |

---

## Opsi 2: Google Gemini (Gratis — Quota Besar)

Google AI Studio memberikan **quota gratis sangat besar** (1500 request/hari).

### Langkah:
1. Buka **https://aistudio.google.com** → Sign in dengan akun Google
2. Klik **Get API key** → **Create API key in new project**
3. Copy API key-nya, lalu jalankan:

```bash
export GEMINI_API_KEY="AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxx"
export STRIX_LLM="gemini/gemini-2.0-flash"

strix scan --target https://target-kamu.com
```

### Model Gemini gratis:
| Model | Keterangan |
|-------|------------|
| `gemini/gemini-2.0-flash` | Cepat, cocok untuk kebanyakan scan |
| `gemini/gemini-2.5-flash-preview-05-20` | Lebih pintar, sedikit lebih lambat |

---

## Opsi 3: Ollama (GRATIS 100% — Offline, Tidak Perlu Internet)

Jalankan LLM langsung di komputer kamu. Tidak perlu API key sama sekali.

### Syarat minimal:
- RAM minimal 8GB (untuk model 7B)
- RAM 16GB+ untuk hasil lebih baik (model 14B-32B)

### Langkah:
```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Download model (pilih salah satu sesuai RAM)
ollama pull phi3:mini               # RAM 8GB   — ringan, 128K context (MIT)
ollama pull qwen2.5-coder:7b        # RAM 8GB   — bagus untuk analisis kode
ollama pull mistral:7b-instruct     # RAM 8GB   — seimbang kecepatan & kualitas (Apache 2.0)
ollama pull phi4                    # RAM 16GB  — reasoning terbaik di kelas 14B (MIT)
ollama pull qwen2.5-coder:14b       # RAM 16GB  — lebih akurat untuk code analysis
ollama pull mixtral:8x7b            # RAM 48GB  — paling pintar, enterprise-grade (Apache 2.0)

# 3. Jalankan Strix
export STRIX_LLM="ollama/phi4"              # Rekomendasi jika RAM 16GB
export STRIX_LLM="ollama/qwen2.5-coder:7b" # Jika RAM hanya 8GB
export LLM_API_BASE="http://localhost:11434"

strix scan --target https://target-kamu.com
```

### Model Ollama terbaik untuk security testing:
| Model | RAM | Lisensi | Kelebihan |
|-------|-----|---------|-----------|
| `phi3:mini` | 8GB | **MIT** | Paling ringan, 128K context |
| `mistral:7b-instruct` | 8GB | **Apache 2.0** | Cepat, instruction-following bagus |
| `qwen2.5-coder:7b` | 8GB | Custom free | Terbaik untuk analisis kode/vuln |
| `phi4` | 16GB | **MIT** | Reasoning terbaik untuk class 14B |
| `qwen2.5-coder:14b` | 16GB | Custom free | Akurasi lebih tinggi |
| `mixtral:8x7b` | 48GB | **Apache 2.0** | Paling cerdas, setara GPT-3.5 |

---

## Quick Start — Pilih Satu & Jalankan

Buat file `.env` di folder strix:

```bash
# Salin salah satu blok ini ke file .env

# === GROQ (gratis, paling cepat) ===
GROQ_API_KEY=gsk_isi_api_key_kamu_disini
STRIX_LLM=groq/llama-3.3-70b-versatile

# === GEMINI (gratis, quota besar) ===
# GEMINI_API_KEY=AIzaSy_isi_api_key_kamu_disini
# STRIX_LLM=gemini/gemini-2.0-flash

# === OLLAMA (offline, tidak perlu internet) ===
# STRIX_LLM=ollama/qwen2.5-coder:7b
# LLM_API_BASE=http://localhost:11434
```

Lalu load dan jalankan:
```bash
source .env
strix scan --target https://target-kamu.com
```

---

## Perbandingan Akhir

| | Groq | Gemini | Ollama |
|-|------|--------|--------|
| **Biaya** | Gratis | Gratis | Gratis |
| **Internet** | Ya | Ya | Tidak perlu |
| **Kecepatan** | ⚡ Tercepat | Cepat | Tergantung PC |
| **Kualitas scan** | ★★★★★ | ★★★★ | ★★★ (phi4) |
| **Privacy** | Data ke Groq | Data ke Google | 100% lokal |
| **Setup** | 5 menit | 5 menit | 10-30 menit |
| **Model terbaik** | llama-3.3-70b | gemini-2.0-flash | phi4 / mistral |

> **Rekomendasi**: Mulai dengan **Groq** — daftar 5 menit, langsung bisa pakai.
> **Untuk privasi maksimal**: Gunakan **Ollama + phi4** — 100% offline, tidak ada data keluar.

---

## Multi-Model (Gunakan 2-3 Model Sekaligus)

Strix mendukung 3 role model yang berbeda secara bersamaan:

| Role | Env Var | Fungsi | Contoh Model |
|------|---------|--------|--------------|
| **main** | `STRIX_LLM` | Reasoning utama, laporan | groq/llama-3.3-70b |
| **fast** | `STRIX_LLM_FAST` | Recon cepat, lookup murah | groq/llama-3.1-8b-instant |
| **code** | `STRIX_LLM_CODE` | Analisis kode, exploit review | ollama/qwen2.5-coder:14b |

Jika `STRIX_LLM_FAST` atau `STRIX_LLM_CODE` tidak diset, otomatis fallback ke `STRIX_LLM`.

### Contoh 1: Groq untuk semua, model berbeda per task
```bash
STRIX_LLM=groq/llama-3.3-70b-versatile          # main: reasoning mendalam
STRIX_LLM_FAST=groq/llama-3.1-8b-instant        # fast: 10x lebih murah, untuk recon
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
```

### Contoh 2: Cloud untuk reasoning, lokal untuk analisis kode (privasi)
```bash
STRIX_LLM=groq/llama-3.3-70b-versatile          # main: cloud, cepat
STRIX_LLM_CODE=ollama/qwen2.5-coder:14b         # code: lokal, data kode tidak keluar
CODE_LLM_API_BASE=http://localhost:11434
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
```

### Contoh 3: Full offline, 3 model Ollama berbeda
```bash
STRIX_LLM=ollama/phi4                            # main: reasoning bagus
STRIX_LLM_FAST=ollama/phi3:mini                  # fast: ringan, cepat
STRIX_LLM_CODE=ollama/qwen2.5-coder:14b          # code: code specialist
LLM_API_BASE=http://localhost:11434
```

### Contoh 4: Gemini + Ollama (gratis total, tanpa Groq)
```bash
STRIX_LLM=gemini/gemini-2.0-flash               # main: free 1500 req/hari
STRIX_LLM_CODE=ollama/qwen2.5-coder:7b          # code: 100% lokal
CODE_LLM_API_BASE=http://localhost:11434
GEMINI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxx
```
