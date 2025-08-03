import subprocess
import time
import os
import sys
import datetime
import pandas as pd
import traceback

# Import functionality from existing modules
from preprocess import preprocess_data
from detect import load_model_and_data, detect_anomalies, save_results, visualize_results

# --- Configuration ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "../data")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "../logs")
ALERT_THRESHOLD = 0.1  # Alert if anomaly percentage exceeds this value
MONITOR_INTERVAL = 30  # seconds between checks

# Control flag to prevent nested executions
MONITORING_FLAG_FILE = os.path.join(os.path.dirname(__file__), "../.monitoring_active")

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)

def is_already_monitoring():
    """Check if monitoring is already running"""
    return os.path.exists(MONITORING_FLAG_FILE)

def set_monitoring_flag():
    """Set flag to indicate monitoring is active"""
    with open(MONITORING_FLAG_FILE, "w") as f:
        f.write(str(datetime.datetime.now()))

def clear_monitoring_flag():
    """Clear monitoring flag when done"""
    if os.path.exists(MONITORING_FLAG_FILE):
        os.remove(MONITORING_FLAG_FILE)

def simulate_network_traffic():
    """
    Instead of capturing live traffic, we'll use the existing processed data
    for demonstration purposes
    """
    print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Using existing data for analysis...")
    return True

def log_alert(results, threshold=ALERT_THRESHOLD):
    """Log an alert when anomalies exceed the threshold"""
    anomaly_count = results['anomaly'].sum() 
    total_count = len(results)
    anomaly_percent = anomaly_count / total_count
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_log_path = os.path.join(LOGS_DIR, "alerts.log")
    
    alert_message = f"[{timestamp}] ALERTE: {anomaly_count} anomalies détectées ({anomaly_percent:.2%})"
    print(f"\n⚠️ {alert_message}")
    
    # Log to file
    with open(alert_log_path, "a") as f:
        f.write(f"{alert_message}\n")
    
    # If anomaly percentage is above threshold, create a detailed alert
    if anomaly_percent >= threshold:
        detailed_alert_path = os.path.join(LOGS_DIR, f"alert_details_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(detailed_alert_path, "w") as f:
            f.write(f"=== ALERTE DE SÉCURITÉ - {timestamp} ===\n\n")
            f.write(f"Nombre total de flux: {total_count}\n")
            f.write(f"Anomalies détectées: {anomaly_count} ({anomaly_percent:.2%})\n\n")
            
            # Include details about the anomalies
            anomalies = results[results['anomaly'] == 1]
            f.write("=== DÉTAILS DES ANOMALIES ===\n\n")
            for i, anomaly in enumerate(anomalies.itertuples(), 1):
                f.write(f"Anomalie #{i}:\n")
                f.write(f"  - Score d'anomalie: {anomaly.anomaly_score:.4f}\n")
                for col in results.columns:
                    if col not in ['anomaly', 'anomaly_score', 'anomaly_type'] and hasattr(anomaly, col.replace(' ', '_').replace('/', '_')):
                        attr_name = col.replace(' ', '_').replace('/', '_')
                        f.write(f"  - {col}: {getattr(anomaly, attr_name)}\n")
                f.write("\n")
        
        print(f"Détails de l'alerte sauvegardés dans: {detailed_alert_path}")

def monitor_network():
    """
    Main function to continuously monitor network traffic for anomalies
    """
    print("\n=== IDS Cyber-IA - Surveillance du Réseau ===\n")
    print(f"Démarrage de la surveillance à {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Intervalle de vérification: {MONITOR_INTERVAL} secondes")
    print(f"Seuil d'alerte: {ALERT_THRESHOLD:.2%} anomalies")
    print("\nAppuyez sur Ctrl+C pour arrêter la surveillance...")
    
    # Check if monitoring is already running
    if is_already_monitoring():
        print("⚠️ Une instance de surveillance est déjà en cours d'exécution.")
        print("Si ce n'est pas le cas, supprimez le fichier .monitoring_active et réessayez.")
        return
    
    # Set monitoring flag
    set_monitoring_flag()
    
    # Prepare monitoring statistics
    monitoring_stats = {
        "start_time": datetime.datetime.now(),
        "checks_performed": 0,
        "anomalies_detected": 0,
        "last_alert": None
    }
    
    try:
        while True:
            print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Vérification #{monitoring_stats['checks_performed'] + 1}...")
            
            # Step 1: Instead of capturing new traffic, we'll use existing data
            simulate_network_traffic()
            
            # Step 2: Load the model and preprocessed data directly
            try:
                model, data, features = load_model_and_data()
            except Exception as e:
                print(f"Erreur lors du chargement du modèle ou des données: {str(e)}")
                traceback.print_exc()
                time.sleep(MONITOR_INTERVAL)
                continue
            
            # Step 3: Detect anomalies
            results = detect_anomalies(model, data)
            monitoring_stats["checks_performed"] += 1
            
            # Step 4: Handle anomalies if any
            anomaly_count = results['anomaly'].sum()
            if anomaly_count > 0:
                monitoring_stats["anomalies_detected"] += anomaly_count
                monitoring_stats["last_alert"] = datetime.datetime.now()
                
                # Log alert and save results
                log_alert(results)
                save_results(results)
                visualize_results(results)
            else:
                print("✅ Aucune anomalie détectée")
            
            # Display monitoring summary
            elapsed = datetime.datetime.now() - monitoring_stats["start_time"]
            elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
            print(f"\nSurveillance en cours depuis {elapsed_str}")
            print(f"Vérifications effectuées: {monitoring_stats['checks_performed']}")
            print(f"Anomalies détectées au total: {monitoring_stats['anomalies_detected']}")
            
            # Wait for the next check
            print(f"Prochaine vérification dans {MONITOR_INTERVAL} secondes...")
            time.sleep(MONITOR_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n\nSurveillance arrêtée par l'utilisateur.")
        
        # Display enhanced final statistics with more detail
        elapsed = datetime.datetime.now() - monitoring_stats["start_time"]
        elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
        print(f"\n=== Résumé de la surveillance ===")
        print(f"Durée totale: {elapsed_str}")
        print(f"Vérifications effectuées: {monitoring_stats['checks_performed']}")
        print(f"Anomalies détectées: {monitoring_stats['anomalies_detected']}")
        
        # Add enhanced statistics reporting
        if monitoring_stats["checks_performed"] > 0:
            anomaly_rate = monitoring_stats["anomalies_detected"] / monitoring_stats["checks_performed"]
            print(f"Taux de détection moyen: {anomaly_rate:.2f} anomalies par vérification")
            
        if monitoring_stats["last_alert"]:
            last_alert_time = monitoring_stats["last_alert"].strftime('%Y-%m-%d %H:%M:%S')
            time_since_last = datetime.datetime.now() - monitoring_stats["last_alert"]
            time_since_str = str(time_since_last).split('.')[0]
            print(f"Dernière alerte: {last_alert_time} (il y a {time_since_str})")
            
        # Save monitoring summary to log file
        summary_path = os.path.join(LOGS_DIR, f"monitoring_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(summary_path, "w") as f:
            f.write(f"=== Résumé de la surveillance - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n")
            f.write(f"Heure de début: {monitoring_stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Durée totale: {elapsed_str}\n")
            f.write(f"Vérifications effectuées: {monitoring_stats['checks_performed']}\n")
            f.write(f"Anomalies détectées: {monitoring_stats['anomalies_detected']}\n")
            if monitoring_stats["last_alert"]:
                f.write(f"Dernière alerte: {monitoring_stats['last_alert'].strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"Résumé de la surveillance sauvegardé dans: {summary_path}")
        print("\nFin de la surveillance.")
    
    finally:
        # Always clear the monitoring flag when done
        clear_monitoring_flag()

if __name__ == "__main__":
    monitor_network()