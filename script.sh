#!/bin/bash
# Script corretto per copiare i README.md nelle posizioni giuste

echo "🔧 Fix setup repository - file già presenti"
echo "============================================="

cd ~/Scaricati/temp

echo "📍 File trovati nella directory corrente:"
ls -la readme_*.md

echo ""
echo "📝 Copia file nelle posizioni corrette..."

# README principale
if [ -f "readme_main.md" ]; then
    echo "📄 Creazione README.md principale..."
    cp readme_main.md README.md
    echo "✅ README.md principale creato"
else
    echo "❌ readme_main.md non trovato!"
fi

# Linux Security
if [ -f "readme_linux.md" ]; then
    echo "📄 Setup Linux Security..."
    cp readme_linux.md docs/linux-security/README.md
    echo "✅ docs/linux-security/README.md creato"
else
    echo "❌ readme_linux.md non trovato!"
fi

# Networking
if [ -f "readme_networking.md" ]; then
    echo "📄 Setup Networking..."
    cp readme_networking.md docs/networking/README.md
    echo "✅ docs/networking/README.md creato"
else
    echo "❌ readme_networking.md non trovato!"
fi

# Defensive Security
if [ -f "readme_defensive.md" ]; then
    echo "📄 Setup Defensive Security..."
    cp readme_defensive.md docs/defensive-security/README.md
    echo "✅ docs/defensive-security/README.md creato"
else
    echo "❌ readme_defensive.md non trovato!"
fi

# Windows Security
if [ -f "readme_windows.md" ]; then
    echo "📄 Setup Windows Security..."
    cp readme_windows.md docs/windows-security/README.md
    echo "✅ docs/windows-security/README.md creato"
else
    echo "❌ readme_windows.md non trovato!"
fi

# Exploits
if [ -f "readme_exploits.md" ]; then
    echo "📄 Setup Exploits..."
    cp readme_exploits.md docs/exploits/README.md
    echo "✅ docs/exploits/README.md creato"
else
    echo "❌ readme_exploits.md non trovato!"
fi

echo ""
echo "🔍 Verifica file creati:"
echo "README.md principale:"
ls -la README.md 2>/dev/null && echo "✅ Trovato" || echo "❌ Non trovato"

echo ""
echo "README.md nelle sezioni:"
for dir in linux-security networking defensive-security windows-security exploits; do
    if [ -f "docs/$dir/README.md" ]; then
        echo "✅ docs/$dir/README.md"
    else
        echo "❌ docs/$dir/README.md"
    fi
done

echo ""
echo "📦 Aggiunta nuovi file a Git..."
git add .

echo "💾 Nuovo commit con file sistemati..."
git commit -m "docs: sistemazione README.md nelle cartelle corrette

📁 Struttura finale:
- README.md (principale con navigation)
- docs/linux-security/README.md  
- docs/networking/README.md
- docs/defensive-security/README.md
- docs/windows-security/README.md
- docs/exploits/README.md

🔗 Tutti i link ora funzionano correttamente"

echo ""
echo "🌐 Struttura finale repository:"
echo "├── README.md"
echo "└── docs/"
echo "    ├── linux-security/README.md"
echo "    ├── networking/README.md" 
echo "    ├── defensive-security/README.md"
echo "    ├── windows-security/README.md"
echo "    └── exploits/README.md"

echo ""
echo "✅ Fix completato!"
echo "🚀 Ora puoi fare: git push origin main"#!/bin/bash
# Script corretto per copiare i README.md nelle posizioni giuste

echo "🔧 Fix setup repository - file già presenti"
echo "============================================="

cd ~/Scaricati/temp

echo "📍 File trovati nella directory corrente:"
ls -la readme_*.md

echo ""
echo "📝 Copia file nelle posizioni corrette..."

# README principale
if [ -f "readme_main.md" ]; then
    echo "📄 Creazione README.md principale..."
    cp readme_main.md README.md
    echo "✅ README.md principale creato"
else
    echo "❌ readme_main.md non trovato!"
fi

# Linux Security
if [ -f "readme_linux.md" ]; then
    echo "📄 Setup Linux Security..."
    cp readme_linux.md docs/linux-security/README.md
    echo "✅ docs/linux-security/README.md creato"
else
    echo "❌ readme_linux.md non trovato!"
fi

# Networking
if [ -f "readme_networking.md" ]; then
    echo "📄 Setup Networking..."
    cp readme_networking.md docs/networking/README.md
    echo "✅ docs/networking/README.md creato"
else
    echo "❌ readme_networking.md non trovato!"
fi

# Defensive Security
if [ -f "readme_defensive.md" ]; then
    echo "📄 Setup Defensive Security..."
    cp readme_defensive.md docs/defensive-security/README.md
    echo "✅ docs/defensive-security/README.md creato"
else
    echo "❌ readme_defensive.md non trovato!"
fi

# Windows Security
if [ -f "readme_windows.md" ]; then
    echo "📄 Setup Windows Security..."
    cp readme_windows.md docs/windows-security/README.md
    echo "✅ docs/windows-security/README.md creato"
else
    echo "❌ readme_windows.md non trovato!"
fi

# Exploits
if [ -f "readme_exploits.md" ]; then
    echo "📄 Setup Exploits..."
    cp readme_exploits.md docs/exploits/README.md
    echo "✅ docs/exploits/README.md creato"
else
    echo "❌ readme_exploits.md non trovato!"
fi

echo ""
echo "🔍 Verifica file creati:"
echo "README.md principale:"
ls -la README.md 2>/dev/null && echo "✅ Trovato" || echo "❌ Non trovato"

echo ""
echo "README.md nelle sezioni:"
for dir in linux-security networking defensive-security windows-security exploits; do
    if [ -f "docs/$dir/README.md" ]; then
        echo "✅ docs/$dir/README.md"
    else
        echo "❌ docs/$dir/README.md"
    fi
done

echo ""
echo "📦 Aggiunta nuovi file a Git..."
git add .

echo "💾 Nuovo commit con file sistemati..."
git commit -m "docs: sistemazione README.md nelle cartelle corrette

📁 Struttura finale:
- README.md (principale con navigation)
- docs/linux-security/README.md  
- docs/networking/README.md
- docs/defensive-security/README.md
- docs/windows-security/README.md
- docs/exploits/README.md

🔗 Tutti i link ora funzionano correttamente"

echo ""
echo "🌐 Struttura finale repository:"
echo "├── README.md"
echo "└── docs/"
echo "    ├── linux-security/README.md"
echo "    ├── networking/README.md" 
echo "    ├── defensive-security/README.md"
echo "    ├── windows-security/README.md"
echo "    └── exploits/README.md"

echo ""
echo "✅ Fix completato!"
echo "🚀 Ora puoi fare: git push origin main"
