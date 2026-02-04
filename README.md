# Template Sécurité Python - ESGI 4A


###  Installer les dépendances

```bash
poetry install
```

---

## Lancer les TPs

### TP1 - Analyse du Trafic Réseau (IDS/IPS)

```bash
# Lister les interfaces réseau
poetry run python -m src.tp1.main --list

# Capture par défaut
poetry run python -m src.tp1.main

# Avec options
poetry run python -m src.tp1.main -t 30 -c 500 -o rapport.pdf

# Spécifier une interface
poetry run python -m src.tp1.main -i "Wi-Fi" -t 10
```
**Options:**
- `-i, --interface` : Interface réseau
- `-t, --time` : Durée en secondes (défaut: 10)
- `-c, --count` : Nombre max de paquets (défaut: 100)
- `-o, --output` : Fichier PDF (défaut: report.pdf)

> **Note:** Nécessite les droits administrateur

---

### TP2 - Analyse de Shellcode

```bash
# Analyser un fichier shellcode
poetry run python -m src.tp2.main -f shellcode.txt

# Sans analyse LLM
poetry run python -m src.tp2.main -f shellcode.txt --no-llm
```

---

### TP3 - Captcha Solver

```bash
# Tous les challenges (1 à 5)
poetry run python -m src.tp3.main

# Un challenge spécifique
poetry run python -m src.tp3.main --challenge 1
poetry run python -m src.tp3.main --challenge 2
poetry run python -m src.tp3.main --challenge 3
poetry run python -m src.tp3.main --challenge 4
poetry run python -m src.tp3.main --challenge 5
```

**FLAGS:**
- Challenge 1: `FLAG-1{1z1_one}`
- Challenge 2: `FLAG-2{4_l1ttl3_h4rder}`
- Challenge 3: `FLAG-3{N0_t1m3_to_Sl33p}`
- Challenge 4: `FLAG-4{B4d_Pr0tection}`
- Challenge 5: `FLAG-5{Th3_l4st_0n3}`

---

### TP4 - Crazy Decoder

```bash
# Lancer le challenge
poetry run python -m src.tp4.main

# Avec options
poetry run python -m src.tp4.main --ip 31.220.95.27 --port 13337 --rounds 150
```

**FLAG:** `ESGI{G00d_Pr0gr4mmer}`

---

## Pre-commit

```bash
# Installer les hooks
poetry run pre-commit install

# Lancer sur tous les fichiers
poetry run pre-commit run --all-files

# Lancer avant un commit (automatique après install)
git commit -m "message"
```

---

## Commandes Poetry utiles

```bash
# Installer les dépendances
poetry install

# Ajouter une dépendance
poetry add requests

# Lancer un script
poetry run python script.py

# Activer l'environnement virtuel
poetry shell

# Voir les dépendances
poetry show
```
