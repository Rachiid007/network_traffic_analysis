#!/bin/bash
# install.sh - Script d'installation de l'IDS pour environnement d'entreprise

set -e

echo "Installation de l'IDS en environnement d'entreprise..."

# Vérification des dépendances système
echo "Vérification des dépendances système..."
command -v python3 >/dev/null 2>&1 || { echo "Python 3 est requis mais n'est pas installé. Abandon."; exit 1; }

# Installation des packages système nécessaires
if command -v apt-get >/dev/null 2>&1; then
    echo "Détection d'une distribution basée sur Debian/Ubuntu"
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-venv tcpdump libpcap-dev
elif command -v yum >/dev/null 2>&1; then
    echo "Détection d'une distribution basée sur RHEL/CentOS"
    sudo yum install -y python3-pip python3-devel tcpdump libpcap-devel
else
    echo "Distribution non prise en charge automatiquement. Veuillez installer manuellement: python3-pip, tcpdump, libpcap-dev"
fi

# Création d'un environnement virtuel
echo "Création de l'environnement virtuel Python..."
python3 -m venv venv
source venv/bin/activate

# Installation des dépendances Python
echo "Installation des dépendances Python..."
pip install -U pip
pip install -r requirements.txt

# Création des répertoires nécessaires
echo "Création des répertoires de travail..."
mkdir -p data logs models config.json

# Création du fichier de configuration par défaut
echo "Création du fichier de configuration..."
cat > config.json/settings.json << EOL
{
    "interface": null,
    "packet_count": 1000,
    "timeout": 60,
    "interval": 300,
    "bpf_filter": "",
    "alert_threshold": 0.8,
    "alert_email": "",
    "save_intermediate": true,
    "detection_sensitivity": 0.7
}
EOL

# Création du service systemd
echo "Création du service systemd..."
cat > ids.service << EOL
[Unit]
Description=Network Intrusion Detection System
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/venv/bin/python app.py --continuous
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

# Affichage des interfaces réseau disponibles
echo "Interfaces réseau disponibles:"
./venv/bin/python src/capture.py --list

echo ""
echo "Installation terminée."
echo ""
echo "Pour configurer le système:"
echo "1. Modifiez config.json/settings.json avec vos paramètres"
echo "2. Pour installer le service: sudo cp ids.service /etc/systemd/system/ && sudo systemctl daemon-reload"
echo "3. Pour démarrer le service: sudo systemctl start ids"
echo "4. Pour l'activer au démarrage: sudo systemctl enable ids"
echo ""
echo "Pour un test manuel: ./venv/bin/python app.py --interface <votre_interface>"
echo ""