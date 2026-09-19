#!/usr/bin/env bash
# setup_free.sh — Konfigurasi Strix dengan LLM gratis
# Jalankan: bash setup_free.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   Strix — Setup LLM Gratis               ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Pilih provider LLM gratis:"
echo ""
echo -e "  ${CYAN}1)${NC} Groq       — Gratis, tercepat, perlu daftar di groq.com"
echo -e "  ${CYAN}2)${NC} Gemini     — Gratis, quota besar, perlu akun Google"
echo -e "  ${CYAN}3)${NC} Ollama     — Gratis, offline, tidak perlu internet"
echo ""
read -rp "Pilihan (1/2/3): " choice

ENV_FILE=".env"

case "$choice" in
  1)
    echo ""
    echo -e "${YELLOW}Groq Setup${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. Buka: https://console.groq.com"
    echo "2. Sign up (gratis) → API Keys → Create API Key"
    echo "3. Paste API key di bawah ini:"
    echo ""
    read -rsp "  Groq API Key (gsk_...): " groq_key
    echo ""

    if [[ -z "$groq_key" ]]; then
      echo -e "${RED}API key tidak boleh kosong.${NC}"
      exit 1
    fi

    echo ""
    echo "Pilih model Groq:"
    echo "  1) llama-3.3-70b-versatile  (direkomendasikan)"
    echo "  2) deepseek-r1-distill-llama-70b"
    echo "  3) qwen-qwq-32b"
    read -rp "Model (1/2/3, default=1): " mChoice
    case "$mChoice" in
      2) model="groq/deepseek-r1-distill-llama-70b" ;;
      3) model="groq/qwen-qwq-32b" ;;
      *) model="groq/llama-3.3-70b-versatile" ;;
    esac

    cat > "$ENV_FILE" <<EOF
# Strix — Groq Free Tier
GROQ_API_KEY=${groq_key}
STRIX_LLM=${model}
EOF
    echo -e "${GREEN}✓ Tersimpan ke .env${NC}"
    ;;

  2)
    echo ""
    echo -e "${YELLOW}Google Gemini Setup${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. Buka: https://aistudio.google.com"
    echo "2. Klik 'Get API key' → 'Create API key'"
    echo "3. Paste API key di bawah ini:"
    echo ""
    read -rsp "  Gemini API Key (AIzaSy...): " gemini_key
    echo ""

    if [[ -z "$gemini_key" ]]; then
      echo -e "${RED}API key tidak boleh kosong.${NC}"
      exit 1
    fi

    echo ""
    echo "Pilih model Gemini:"
    echo "  1) gemini-2.0-flash         (cepat, direkomendasikan)"
    echo "  2) gemini-2.5-flash-preview-05-20  (lebih pintar)"
    read -rp "Model (1/2, default=1): " mChoice
    case "$mChoice" in
      2) model="gemini/gemini-2.5-flash-preview-05-20" ;;
      *) model="gemini/gemini-2.0-flash" ;;
    esac

    cat > "$ENV_FILE" <<EOF
# Strix — Google Gemini Free Tier
GEMINI_API_KEY=${gemini_key}
STRIX_LLM=${model}
EOF
    echo -e "${GREEN}✓ Tersimpan ke .env${NC}"
    ;;

  3)
    echo ""
    echo -e "${YELLOW}Ollama Setup (Offline)${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Check if ollama is installed
    if ! command -v ollama &>/dev/null; then
      echo "Ollama belum terinstall. Install sekarang? (y/n)"
      read -rp "  " install_choice
      if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then
        echo "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
      else
        echo ""
        echo "Install manual: https://ollama.com/download"
        echo "Lalu jalankan script ini lagi."
        exit 0
      fi
    fi

    echo ""
    echo "Berapa RAM komputer kamu?"
    echo "  1) 8GB   → qwen2.5-coder:7b   (~4.5 GB download)"
    echo "  2) 16GB  → qwen2.5-coder:14b  (~9 GB download)"
    echo "  3) 16GB+ → qwen3:14b          (~9 GB download, lebih pintar)"
    read -rp "Pilihan (1/2/3, default=1): " ramChoice
    case "$ramChoice" in
      2) ollamaModel="qwen2.5-coder:14b" ;;
      3) ollamaModel="qwen3:14b" ;;
      *) ollamaModel="qwen2.5-coder:7b" ;;
    esac

    echo ""
    echo -e "Mendownload model ${CYAN}${ollamaModel}${NC} (mungkin perlu beberapa menit)..."
    ollama pull "$ollamaModel"

    cat > "$ENV_FILE" <<EOF
# Strix — Ollama (Offline, Gratis)
STRIX_LLM=ollama/${ollamaModel}
LLM_API_BASE=http://localhost:11434
EOF
    echo -e "${GREEN}✓ Tersimpan ke .env${NC}"
    echo ""
    echo -e "${YELLOW}Pastikan Ollama sudah berjalan:${NC}"
    echo "  ollama serve"
    ;;

  *)
    echo -e "${RED}Pilihan tidak valid.${NC}"
    exit 1
    ;;
esac

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Setup selesai! Cara menjalankan Strix:${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  # Load konfigurasi"
echo "  source .env"
echo ""
echo "  # Jalankan scan (ganti URL dengan target kamu)"
echo "  strix scan --target https://target-kamu.com"
echo ""
echo "  # Atau dengan authorization gate (direkomendasikan)"
echo "  strix auth-scope init --target https://target-kamu.com --authorized-by 'Nama Kamu'"
echo "  strix scan --target https://target-kamu.com --auth-enforce"
echo ""
echo -e "${YELLOW}Baca FREE_SETUP.md untuk info lebih lengkap.${NC}"
echo ""
