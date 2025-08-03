import os
import subprocess
import sys
import time
import argparse
import signal
import logging
import datetime

# Configuration du logger
log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "ids.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("IDS")

def create_dirs():
    """Crée les répertoires nécessaires s'ils n'existent pas"""
    base_dir = os.path.dirname(os.path.dirname(__file__))
    os.makedirs(os.path.join(base_dir, "data"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "models"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "config"), exist_ok=True)

def run_script(script_path, additional_args=None):
    """Exécute un script Python et retourne son code de sortie"""
    # Vérifier si le chemin est absolu ou relatif
    if not os.path.isabs(script_path):
        # Tenter de résoudre le chemin relatif
        base_dir = os.path.dirname(__file__)
        abs_script_path = os.path.join(base_dir, script_path)
        if os.path.exists(abs_script_path):
            script_path = abs_script_path
    
    if os.path.exists(script_path):
        logger.info(f"Exécution de {script_path}...")
        cmd = [sys.executable, script_path]
        if additional_args:
            cmd.extend(additional_args)
        try:
            result = subprocess.run(cmd, check=False)
            return result.returncode
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de {script_path}: {str(e)}")
            return 1
    else:
        logger.error(f"Erreur: {script_path} introuvable.")
        return 1

def show_banner():
    title = "yemak"
    print(title)
    print("\nBienvenue sur NeuroShield Enterprise Edition.")
    print("Système de Détection d'Intrusion basé sur l'Intelligence Artificielle.")

def signal_handler(sig, frame):
    """Gestionnaire de signal pour arrêter proprement le programme"""
    logger.info("Arrêt demandé, terminaison du programme...")
    sys.exit(0)

def send_alert(message, alert_level="WARNING"):
    """Envoie une alerte (placeholder pour l'intégration future)"""
    logger.warning(f"ALERTE [{alert_level}]: {message}")
    # Ici, on pourrait implémenter l'envoi d'email, SMS, ou intégration avec un SIEM

if __name__ == "__main__":
    # Enregistrement du gestionnaire de signal pour CTRL+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Création des répertoires nécessaires
    create_dirs()

    # Analyse des arguments de ligne de commande
    parser = argparse.ArgumentParser(description='Système de détection d\'intrusions basé sur l\'IA')
    parser.add_argument('--continuous', '-c', action='store_true', help='Exécution en continu')
    parser.add_argument('--interval', '-i', type=int, default=60, help='Intervalle entre les analyses (en secondes)')
    parser.add_argument('--train', '-t', action='store_true', help='Entraîner le modèle')
    parser.add_argument('--interface', '-if', help='Interface réseau à surveiller')
    parser.add_argument('--list-interfaces', '-li', action='store_true', help='Lister les interfaces disponibles')
    parser.add_argument('--packet-count', '-pc', type=int, default=1000, help='Nombre de paquets à capturer')
    parser.add_argument('--timeout', '-to', type=int, default=60, help='Timeout de la capture (secondes)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    args = parser.parse_args()

    # Configuration du niveau de log
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Affichage de la bannière
    show_banner()
    
    # Chemins des scripts avec chemins absolus
    base_dir = os.path.dirname(os.path.dirname(__file__))
    capture_script = os.path.join(base_dir, "src", "capture.py")
    preprocess_script = os.path.join(base_dir, "src", "preprocess.py")
    detect_script = os.path.join(base_dir, "src", "detect.py")
    train_script = os.path.join(base_dir, "models", "train_model.py")
    
    # Lister les interfaces si demandé
    if args.list_interfaces:
        run_script(capture_script, ["--list"])
        sys.exit(0)
    
    # Préparation des arguments pour capture.py
    capture_args = []
    if args.interface:
        capture_args.extend(["--interface", args.interface])
    if args.packet_count:
        capture_args.extend(["--packet-count", str(args.packet_count)])
    if args.timeout:
        capture_args.extend(["--timeout", str(args.timeout)])

    # Entraînement du modèle si demandé
    if args.train:
        logger.info("===  ENTRAÎNEMENT DU MODÈLE  ===")
        train_result = run_script(train_script)
        if train_result != 0:
            logger.error("Erreur lors de l'entraînement du modèle. Arrêt du programme.")
            sys.exit(1)
        logger.info("Modèle entraîné avec succès!")
    
    # Mode continu ou analyse unique
    if args.continuous:
        logger.info(f"===  DÉMARRAGE DE LA SURVEILLANCE EN TEMPS RÉEL (intervalle: {args.interval}s)  ===")
        logger.info("Appuyez sur Ctrl+C pour arrêter la surveillance.")
        
        cycle = 1
        try:
            while True:
                logger.info(f"--- Cycle d'analyse #{cycle} ---")
                start_time = time.time()
                
                # 1. Capture du trafic réseau
                if run_script(capture_script, capture_args) != 0:
                    logger.error("Erreur lors de la capture. Tentative à la prochaine itération.")
                    time.sleep(args.interval)
                    cycle += 1
                    continue
                
                # 2. Prétraitement des données
                if run_script(preprocess_script) != 0:
                    logger.error("Erreur lors du prétraitement. Tentative à la prochaine itération.")
                    time.sleep(args.interval)
                    cycle += 1
                    continue
                
                # 3. Détection des intrusions
                detect_result = run_script(detect_script)
                
                # Vérification des résultats pour alertes
                if os.path.exists("logs/detection_results.csv"):
                    try:
                        import pandas as pd
                        results = pd.read_csv("logs/detection_results.csv")
                        intrusions = results[results["Prediction"] == 1]
                        if len(intrusions) > 0:
                            alert_msg = f"{len(intrusions)} intrusions potentielles détectées sur {len(results)} connexions analysées"
                            send_alert(alert_msg, "CRITICAL" if len(intrusions) > 5 else "WARNING")
                    except Exception as e:
                        logger.error(f"Erreur lors de l'analyse des résultats: {str(e)}")
                
                # Calcul du temps d'exécution et attente
                execution_time = time.time() - start_time
                wait_time = max(0, args.interval - execution_time)
                
                logger.info(f"Analyse #{cycle} terminée en {execution_time:.1f}s! Attente de {wait_time:.1f}s pour le prochain cycle...")
                cycle += 1
                if wait_time > 0:
                    time.sleep(wait_time)
                
        except KeyboardInterrupt:
            logger.info("Surveillance arrêtée par l'utilisateur.")
    else:
        logger.info("===  DÉMARRAGE D'UNE ANALYSE UNIQUE  ===")
        
        # 1. Capture du trafic réseau
        if run_script(capture_script, capture_args) != 0:
            logger.error("Erreur lors de la capture. Arrêt du programme.")
            sys.exit(1)
        
        # 2. Prétraitement des données
        if run_script(preprocess_script) != 0:
            logger.error("Erreur lors du prétraitement. Arrêt du programme.")
            sys.exit(1)
        
        # 3. Détection des intrusions
        detect_result = run_script(detect_script)
        
        # Vérification des résultats pour alertes
        if os.path.exists("logs/detection_results.csv"):
            try:
                import pandas as pd
                results = pd.read_csv("logs/detection_results.csv")
                intrusions = results[results["Prediction"] == 1]
                if len(intrusions) > 0:
                    alert_msg = f"{len(intrusions)} intrusions potentielles détectées sur {len(results)} connexions analysées"
                    send_alert(alert_msg, "CRITICAL" if len(intrusions) > 5 else "WARNING")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des résultats: {str(e)}")
        
        logger.info("Analyse terminée !")