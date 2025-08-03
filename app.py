import os
import sys
import time
import logging
import pandas as pd
import subprocess
import datetime
import smtplib
import shutil
import json
import argparse
import traceback
from email.message import EmailMessage

# Création des répertoires nécessaires avec chemins absolus
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "config"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, "logs", "alert_system.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AlertSystem")

# Chemins vers les scripts
CAPTURE_SCRIPT = os.path.join(BASE_DIR, "src", "capture.py")
PREPROCESS_SCRIPT = os.path.join(BASE_DIR, "src", "preprocess.py")
DETECT_SCRIPT = os.path.join(BASE_DIR, "src", "detect.py")

def load_config(config_path="config/alert_config.json"):
    """Charge la configuration des alertes"""
    default_config = {
        "email": {
            "enabled": False,
            "smtp_server": "smtp.entreprise.com",
            "smtp_port": 587,
            "username": "ids@entreprise.com",
            "password_env_var": "IDS_EMAIL_PASSWORD",  # Variable d'environnement pour le mot de passe
            "from_address": "ids@entreprise.com",
            "to_addresses": ["securite@entreprise.com"]
        },
        "thresholds": {
            "warning": 1,
            "critical": 5
        },
        "check_interval": 300,
        "alert_cooldown": 3600
    }
    
    if not os.path.exists(config_path):
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(default_config, f, indent=4)
        logger.info(f"Configuration par défaut créée dans {config_path}")
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Erreur lors de la lecture de la configuration ({config_path}): {e}")
        return default_config

def send_email_alert(subject, body, config):
    """Envoie une alerte par email"""
    if not config["email"]["enabled"]:
        logger.info("Alertes email désactivées")
        return False
    
    password = os.getenv(config["email"].get("password_env_var"))
    if not password:
        logger.error(f"Le mot de passe pour l'email n'est pas configuré. "
                     f"Veuillez définir la variable d'environnement '{config['email'].get('password_env_var')}'.")
        return False
        
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = config["email"]["from_address"]
        msg['To'] = ", ".join(config["email"]["to_addresses"])
        msg.set_content(body)
        
        with smtplib.SMTP(config["email"]["smtp_server"], config["email"]["smtp_port"]) as server:
            server.starttls()
            server.login(config["email"]["username"], password)
            server.send_message(msg)
        
        logger.info(f"Email d'alerte envoyé à {', '.join(config['email']['to_addresses'])}")
        return True
    except smtplib.SMTPException as e:
        logger.error(f"Erreur SMTP lors de l'envoi de l'email: {e}")
        return False
    except Exception as e:
        logger.error(f"Erreur inattendue lors de l'envoi de l'email: {e}")
        return False

def check_for_intrusions(config):
    """Vérifie s'il y a de nouvelles intrusions détectées"""
    results_path = "logs/detection_results.csv"
    last_alert_file = "logs/last_alert.txt"
    
    if not os.path.exists(results_path):
        logger.warning(f"Le fichier {results_path} n'existe pas encore")
        return

    # Vérifier quand la dernière alerte a été envoyée
    last_alert_time = 0
    if os.path.exists(last_alert_file):
        try:
            with open(last_alert_file, 'r') as f:
                content = f.read().strip()
                if content:
                    last_alert_time = float(content)
        except (IOError, ValueError) as e:
            logger.error(f"Erreur en lisant le fichier de dernière alerte: {e}")
            pass
    
    # Vérifier si le cooldown est encore actif
    current_time = time.time()
    if current_time - last_alert_time < config["alert_cooldown"]:
        time_left = int(config["alert_cooldown"] - (current_time - last_alert_time))
        logger.info(f"Période de silence active. Prochaine alerte possible dans {time_left} secondes")
        return
    
    try:
        # Pour éviter les race conditions, copier le fichier avant de le lire
        temp_results_path = f"{results_path}.tmp"
        shutil.copy(results_path, temp_results_path)
        results = pd.read_csv(temp_results_path)
        os.remove(temp_results_path)

        # Vérifier si la colonne "Prediction" existe, sinon utiliser "Intrusion_Detected"
        if "Prediction" in results.columns:
            intrusions = results[results["Prediction"] == 1]
        elif "Intrusion_Detected" in results.columns:
            intrusions = results[results["Intrusion_Detected"] == 1]
        else:
            logger.error("Format de fichier de détection non reconnu")
            return
        
        if len(intrusions) == 0:
            logger.info("Aucune intrusion détectée")
            return
        
        # Déterminer le niveau d'alerte
        alert_level = "NORMAL"
        if len(intrusions) >= config["thresholds"]["critical"]:
            alert_level = "CRITICAL"
        elif len(intrusions) >= config["thresholds"]["warning"]:
            alert_level = "WARNING"
        else:
            logger.info(f"{len(intrusions)} intrusions détectées, sous le seuil d'alerte")
            return
        
        # Créer le message d'alerte
        subject = f"[{alert_level}] IDS: {len(intrusions)} intrusions détectées"
        body = f"""
        {len(intrusions)} intrusions potentielles détectées sur {len(results)} connexions analysées.
        
        Détails des 5 premières intrusions:
        """
        
        # Ajouter les détails des intrusions
        for i, (_, row) in enumerate(intrusions.head(5).iterrows()):
            flags = []
            if "SYN Flag Count" in row and row["SYN Flag Count"] > 0: flags.append("SYN")
            if "ACK Flag Count" in row and row["ACK Flag Count"] > 0: flags.append("ACK")
            if "PSH Flag Count" in row and row["PSH Flag Count"] > 0: flags.append("PSH")
            if "FIN Flag Count" in row and row["FIN Flag Count"] > 0: flags.append("FIN")
            flags_str = ", ".join(flags) if flags else "aucun"
            
            body += f"\n{i+1}. Flags: {flags_str}, Durée: {row.get('Flow Duration', 'N/A')}, "
            body += f"Paquets: {int(row.get('Total Fwd Packets', 0) + row.get('Total Backward Packets', 0))}"
        
        # Ajouter l'horodatage
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body += f"\n\nCette alerte a été générée le {now}."
        
        # Envoyer l'alerte
        logger.warning(f"{alert_level}: {len(intrusions)} intrusions détectées")
        
        # Mettre à jour le timestamp de dernière alerte AVANT d'envoyer l'email
        with open(last_alert_file, 'w') as f:
            f.write(str(current_time))

        # Envoyer l'email si configuré
        send_email_alert(subject, body, config)
        
    except pd.errors.EmptyDataError:
        logger.warning(f"Le fichier de résultats {results_path} est vide.")
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des intrusions: {e}")

def run_alert_system(config):
    """Exécute le système d'alerte en continu"""
    logger.info(f"Système d'alerte démarré. Vérification toutes les {config['check_interval']} secondes")
    
    try:
        while True:
            check_for_intrusions(config)
            time.sleep(config["check_interval"])
    except KeyboardInterrupt:
        logger.info("Système d'alerte arrêté par l'utilisateur")

def run_script(script_path, args=[]):
    """Exécute un script Python avec les arguments spécifiés"""
    if not os.path.exists(script_path):
        logger.error(f"Le script {script_path} n'existe pas")
        return -1
        
    cmd = [sys.executable, script_path] + args
    logger.info(f"Exécution de {script_path}...")
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if stdout.strip():
            logger.info(stdout.strip())
        if stderr.strip():
            logger.warning(stderr.strip())
            
        if process.returncode != 0:
            logger.error(f"Erreur lors de l'exécution de {script_path} (code {process.returncode})")
            return process.returncode
        return 0
    except Exception as e:
        logger.error(f"Exception lors de l'exécution de {script_path}: {e}")
        logger.debug(traceback.format_exc())
        return -1

def run_ids_pipeline(args):
    """Exécute le pipeline complet de détection d'intrusion"""
    # Préparer les arguments pour capture.py
    capture_args = []
    if args.interface:
        capture_args.extend(["--interface", args.interface])
    if args.packet_count:
        capture_args.extend(["--packet-count", str(args.packet_count)])
    if args.timeout:
        capture_args.extend(["--timeout", str(args.timeout)])
    if getattr(args, 'list_interfaces', False):
        capture_args.append("--list-interfaces")
        
    # Exécuter la capture
    capture_result = run_script(CAPTURE_SCRIPT, capture_args)
    if capture_result != 0:
        logger.error("Erreur lors de la capture. Arrêt du pipeline.")
        return False
        
    # Exécuter le prétraitement
    preprocess_result = run_script(PREPROCESS_SCRIPT)
    if preprocess_result != 0:
        logger.error("Erreur lors du prétraitement. Arrêt du pipeline.")
        return False
        
    # Exécuter la détection
    detect_result = run_script(DETECT_SCRIPT)
    if detect_result != 0:
        logger.warning("La détection a terminé avec des avertissements.")
    
    logger.info("Pipeline de détection d'intrusion terminé avec succès.")
    return True

def run_continuous_monitoring(args, config):
    """Exécute le pipeline en continu selon l'intervalle spécifié"""
    logger.info(f"===  DÉMARRAGE DE LA SURVEILLANCE EN TEMPS RÉEL (intervalle: {args.interval}s)  ===")
    logger.info("Appuyez sur Ctrl+C pour arrêter la surveillance.")
    
    cycle = 1
    try:
        while True:
            logger.info(f"--- Cycle d'analyse #{cycle} ---")
            start_time = time.time()
            
            # Exécuter le pipeline
            success = run_ids_pipeline(args)
            if success:
                # Vérifier les alertes
                check_for_intrusions(config)
                
            # Calcul du temps d'exécution et attente
            execution_time = time.time() - start_time
            wait_time = max(0, args.interval - execution_time)
            
            logger.info(f"Analyse #{cycle} terminée en {execution_time:.1f}s! Attente de {wait_time:.1f}s pour le prochain cycle...")
            cycle += 1
            
            if wait_time > 0:
                time.sleep(wait_time)
                
    except KeyboardInterrupt:
        logger.info("Surveillance arrêtée par l'utilisateur")

def main():
    # Configuration de l'analyseur d'arguments
    parser = argparse.ArgumentParser(description="Système de Détection d'Intrusion basé sur l'Intelligence Artificielle")
    
    # Arguments généraux
    parser.add_argument('--config', default='config/alert_config.json', help='Chemin vers le fichier de configuration des alertes')
    parser.add_argument('--verbose', '-v', action='store_true', help='Afficher plus de détails pendant l\'exécution')
    
    # Sous-commandes
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Sous-commande 'run': Exécuter une analyse unique
    run_parser = subparsers.add_parser('run', help='Exécuter une analyse unique')
    run_parser.add_argument('--interface', '-i', help='Interface réseau à surveiller')
    run_parser.add_argument('--packet-count', '-pc', type=int, default=1000, help='Nombre de paquets à capturer')
    run_parser.add_argument('--timeout', '-t', type=int, default=60, help='Délai d\'expiration pour la capture (secondes)')
    run_parser.add_argument('--list-interfaces', '-li', action='store_true', help='Lister les interfaces réseau disponibles')
    
    # Sous-commande 'monitor': Surveillance continue
    monitor_parser = subparsers.add_parser('monitor', help='Exécuter la surveillance en continu')
    monitor_parser.add_argument('--interval', '-in', type=int, default=300, help='Intervalle entre les analyses (secondes)')
    monitor_parser.add_argument('--interface', '-i', help='Interface réseau à surveiller')
    monitor_parser.add_argument('--packet-count', '-pc', type=int, default=1000, help='Nombre de paquets à capturer par cycle')
    monitor_parser.add_argument('--timeout', '-t', type=int, default=60, help='Délai d\'expiration pour la capture (secondes)')
    
    # Sous-commande 'alert': Système d'alertes
    alert_parser = subparsers.add_parser('alert', help='Gérer les alertes')
    alert_parser.add_argument('--check', '-c', action='store_true', help='Vérifier une seule fois et quitter')
    alert_parser.add_argument('--daemon', '-d', action='store_true', help='Exécuter en mode daemon (continu)')
    
    # Sous-commande 'train': Entraîner le modèle
    train_parser = subparsers.add_parser('train', help='Entraîner le modèle de détection d\'anomalies')
    train_parser.add_argument('--data', help='Chemin vers les données d\'entraînement étiquetées')
    train_parser.add_argument('--contamination', type=float, default=0.1, 
                        help='Proportion attendue d\'anomalies (par défaut: 0.1)')
    
    # Traitement des arguments
    args = parser.parse_args()
    
    # Afficher la bannière
    print("\nBienvenue sur NeuroShield Enterprise Edition.")
    print("Système de Détection d'Intrusion basé sur l'Intelligence Artificielle.")
    
    # Configuration du niveau de log
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info("Mode verbeux activé")  # Ajout d'un message pour le mode verbeux
        
    # Chargement de la configuration
    config = load_config(args.config)
    
    # Traitement des commandes
    if args.command == 'run':
        run_ids_pipeline(args)
    elif args.command == 'monitor':
        run_continuous_monitoring(args, config)
    elif args.command == 'alert':
        if args.check:
            check_for_intrusions(config)
        elif args.daemon:
            run_alert_system(config)
        else:
            alert_parser.print_help()  # Afficher l'aide si aucune option n'est fournie
    elif args.command == 'train':
        logger.info("Démarrage de l'entraînement du modèle...")
        train_script = os.path.join(BASE_DIR, "src", "train_model.py")
        train_args = []
        if args.data:
            train_args.extend(["--data", args.data])
        if args.contamination:
            train_args.extend(["--contamination", str(args.contamination)])
        result = run_script(train_script, train_args)
        if result == 0:
            logger.info("Entraînement du modèle terminé avec succès")
        else:
            logger.error("Erreur lors de l'entraînement du modèle")
    else:
        parser.print_help()  # Afficher l'aide générale si aucune commande n'est spécifiée

if __name__ == "__main__":
    main()