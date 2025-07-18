#!/bin/bash
# Script per setup finale repository con README.md corretti

echo "🚀 Setup finale repository Sicurezza-Informatica"
echo "================================================"

# Vai nella directory principale del progetto
cd ~/Scaricati/temp

# Inizializza git se non presente
if [ ! -d ".git" ]; then
    echo "📦 Inizializzazione repository Git..."
    git init
fi

echo "📁 Creazione/verifica struttura directory..."
# Le directory esistono già, verifichiamo
if [ -d "docs" ]; then
    echo "✅ Directory docs/ trovata"
else
    echo "❌ Directory docs/ non trovata!"
    exit 1
fi

echo "📝 Rinominazione e posizionamento README.md..."

# README principale
if [ -f "docs/readme_main.md" ]; then
    echo "📄 Creazione README.md principale..."
    cp docs/readme_main.md README.md
    echo "✅ README.md principale creato"
else
    echo "❌ readme_main.md non trovato!"
fi

# Linux Security
if [ -f "docs/readme_linux.md" ]; then
    echo "📄 Setup Linux Security..."
    cp docs/readme_linux.md docs/linux-security/README.md
    echo "✅ docs/linux-security/README.md creato"
else
    echo "❌ readme_linux.md non trovato!"
fi

# Networking
if [ -f "docs/readme_networking.md" ]; then
    echo "📄 Setup Networking..."
    cp docs/readme_networking.md docs/networking/README.md
    echo "✅ docs/networking/README.md creato"
else
    echo "❌ readme_networking.md non trovato!"
fi

# Defensive Security
if [ -f "docs/readme_defensive.md" ]; then
    echo "📄 Setup Defensive Security..."
    cp docs/readme_defensive.md docs/defensive-security/README.md
    echo "✅ docs/defensive-security/README.md creato"
else
    echo "❌ readme_defensive.md non trovato!"
fi

# Windows Security
if [ -f "docs/readme_windows.md" ]; then
    echo "📄 Setup Windows Security..."
    cp docs/readme_windows.md docs/windows-security/README.md
    echo "✅ docs/windows-security/README.md creato"
else
    echo "❌ readme_windows.md non trovato!"
fi

# Exploits
if [ -f "docs/readme_exploits.md" ]; then
    echo "📄 Setup Exploits..."
    cp docs/readme_exploits.md docs/exploits/README.md
    echo "✅ docs/exploits/README.md creato"
else
    echo "❌ readme_exploits.md non trovato!"
fi

echo ""
echo "🔗 Verifica struttura finale:"
echo "├── README.md (principale)"
echo "└── docs/"
echo "    ├── linux-security/README.md"
echo "    ├── networking/README.md"
echo "    ├── defensive-security/README.md"
echo "    ├── windows-security/README.md"
echo "    └── exploits/README.md"

echo ""
echo "📦 Aggiunta file a Git..."
git add .

echo "💾 Commit con messaggio 'giorno 3'..."
git commit -m "giorno 3

📚 Documentazione completa cybersecurity:
- Linux Security (capabilities, ACL, exploits)  
- Networking (packet analysis, port scanning)
- Defensive Security (logging, firewall, detection)
- Windows Security (PowerShell, registry, forensics)
- Exploit Development (privilege escalation, persistence)

🎯 Percorso 3+ giorni: da beginner a intermediate-advanced
⚠️ Tutti i test in ambiente controllato per scopi educativi"

echo ""
echo "✅ Repository setup completato!"
echo ""
echo "🔍 Verifica file creati:"
ls -la README.md
ls -la docs/*/README.md

echo ""
echo "🌐 I link tra le sezioni funzioneranno automaticamente su GitHub:"
echo "- README.md principale → docs/[sezione]/"
echo "- Ogni sezione ha navigation ← → tra documenti"
echo ""
echo "🚀 Pronto per: git push origin main"
