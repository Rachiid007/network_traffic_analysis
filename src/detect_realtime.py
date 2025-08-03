import pandas as pd
import numpy as np
import os
import time
import joblib
import datetime
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import seaborn as sns
from sklearn.preprocessing import StandardScaler
import threading
import logging
from collections import deque
import traceback
import socket
from scapy.all import sniff, IP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "../logs/detection.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('IDS-Detection')

# --- Configuration ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "../data")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "../models")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "../logs")
VISUALIZATIONS_DIR = os.path.join(os.path.dirname(__file__), "../visualizations")

# Create directories if they don't exist
for directory in [DATA_DIR, MODELS_DIR, LOGS_DIR, VISUALIZATIONS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Paths
MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_detector.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODELS_DIR, "features.txt")
TEMP_DATA_PATH = os.path.join(DATA_DIR, "temp_traffic.csv")
ALERTS_LOG_PATH = os.path.join(LOGS_DIR, "alerts.csv")

# Detection settings
DETECTION_INTERVAL = 5  # seconds between detection runs
MAX_HISTORY = 100       # number of data points to keep in history for visualization
PACKET_BUFFER_SIZE = 50 # number of packets to collect before analysis

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.features = []
        self.history = deque(maxlen=MAX_HISTORY)
        self.anomaly_history = deque(maxlen=MAX_HISTORY)
        self.time_history = deque(maxlen=MAX_HISTORY)
        self.alert_count = 0
        self.load_model()
        
    def load_model(self):
        """Load the trained model, scaler and expected features"""
        try:
            if not os.path.exists(MODEL_PATH):
                raise FileNotFoundError(f"Le modèle '{MODEL_PATH}' est introuvable. Lancez 'train_model.py' d'abord.")
            
            self.model = joblib.load(MODEL_PATH)
            logger.info(f"Modèle chargé depuis : {MODEL_PATH}")
            
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
                logger.info(f"Scaler chargé depuis : {SCALER_PATH}")
            else:
                logger.warning(f"Scaler introuvable : {SCALER_PATH}. Les données devront être déjà normalisées.")
            
            if os.path.exists(FEATURES_PATH):
                with open(FEATURES_PATH, 'r') as f:
                    self.features = [line.strip() for line in f.readlines()]
                logger.info(f"{len(self.features)} caractéristiques chargées depuis : {FEATURES_PATH}")
            else:
                logger.warning(f"Liste de caractéristiques introuvable : {FEATURES_PATH}")
        
        except Exception as e:
            logger.error(f"Erreur lors du chargement du modèle : {str(e)}")
            raise
    
    def preprocess_data(self, df):
        """Preprocess data the same way as during training"""
        # Check for missing features and add them with 0 values
        for feature in self.features:
            if feature not in df.columns:
                df[feature] = 0
                logger.debug(f"Ajout de la colonne manquante: {feature}")
        
        # Keep only the features expected by the model
        df = df[self.features].copy()
        
        # Replace infinities with NaN and then with median
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        if df.isnull().values.any():
            df.fillna(df.median(), inplace=True)
        
        # Apply scaling if we have a scaler
        if self.scaler:
            scaled_data = self.scaler.transform(df)
            df = pd.DataFrame(scaled_data, columns=self.features)
        
        return df
    
    def detect(self, data):
        """Detect anomalies in the given data"""
        try:
            if isinstance(data, str) and os.path.exists(data):
                # Load data from file
                df = pd.read_csv(data)
            elif isinstance(data, pd.DataFrame):
                # Use the provided DataFrame
                df = data
            else:
                raise ValueError("Les données doivent être un DataFrame pandas ou un chemin vers un fichier CSV")
            
            if df.empty:
                logger.warning("Aucune donnée à analyser")
                return pd.DataFrame(), 0
            
            # Preprocess data
            df_processed = self.preprocess_data(df)
            
            # Make predictions
            predictions = self.model.predict(df_processed)
            scores = self.model.decision_function(df_processed)
            
            # Convert predictions to a more readable format (1 for anomaly, 0 for normal)
            anomalies = np.where(predictions == -1, 1, 0)
            anomaly_count = np.sum(anomalies)
            
            # Add results to the DataFrame
            df['anomaly'] = anomalies
            df['anomaly_score'] = scores
            
            # Update history for visualization
            current_time = datetime.datetime.now()
            for _, row in df.iterrows():
                self.history.append(row['anomaly_score'])
                self.anomaly_history.append(row['anomaly'])
                self.time_history.append(current_time)
            
            # Log anomalies
            if anomaly_count > 0:
                self.alert_count += anomaly_count
                anomalies_df = df[df['anomaly'] == 1]
                logger.warning(f"⚠️ {anomaly_count} anomalies détectées!")
                
                # Save anomalies to alert log
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                anomalies_df.to_csv(os.path.join(LOGS_DIR, f"alert_{timestamp}.csv"), index=False)
                
                # Append to the main alerts log
                if os.path.exists(ALERTS_LOG_PATH):
                    alerts_df = pd.read_csv(ALERTS_LOG_PATH)
                    alerts_df = pd.concat([alerts_df, anomalies_df])
                    alerts_df.to_csv(ALERTS_LOG_PATH, index=False)
                else:
                    anomalies_df.to_csv(ALERTS_LOG_PATH, index=False)
            
            return df, anomaly_count
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection: {str(e)}")
            raise
    
    def visualize_history(self):
        """Create a visualization of detection history"""
        try:
            if not self.history:
                logger.info("Pas de données historiques à visualiser")
                return
                
            # Create visualization directory if it doesn't exist
            os.makedirs(VISUALIZATIONS_DIR, exist_ok=True)
            
            plt.figure(figsize=(12, 8))
            
            # Plot 1: Anomaly scores over time
            plt.subplot(2, 1, 1)
            times = [t.strftime('%H:%M:%S') for t in self.time_history]
            plt.plot(times, self.history, marker='.', linestyle='-', alpha=0.7)
            plt.axhline(y=0, color='r', linestyle='--', alpha=0.5)
            plt.title('Scores d\'anomalie au fil du temps')
            plt.ylabel('Score')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            # Plot 2: Anomaly counts over time
            plt.subplot(2, 1, 2)
            anomalies = np.array(self.anomaly_history)
            times = np.array(times)
            
            if sum(anomalies) > 0:
                plt.bar(times[anomalies == 1], [1] * sum(anomalies), color='red', alpha=0.7)
            
            plt.title('Détections d\'anomalies')
            plt.ylabel('Détecté')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Save the visualization
            viz_path = os.path.join(VISUALIZATIONS_DIR, "detection_history.png")
            plt.savefig(viz_path)
            plt.close()
            
            logger.info(f"Visualisation sauvegardée dans {viz_path}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de la visualisation: {str(e)}")

# Packet capture and processing
class PacketProcessor:
    def __init__(self):
        self.packets = []
        self.packet_lock = threading.Lock()
        self.features = {}
        self.feature_names = []
        self.load_feature_names()
        
    def load_feature_names(self):
        if os.path.exists(FEATURES_PATH):
            with open(FEATURES_PATH, 'r') as f:
                self.feature_names = [line.strip() for line in f.readlines()]
            logger.info(f"Caractéristiques chargées: {len(self.feature_names)}")
        else:
            logger.warning("Fichier de caractéristiques non trouvé")
    
    def process_packet(self, packet):
        """Process a captured packet"""
        try:
            with self.packet_lock:
                # Extract basic features from packet
                if IP in packet:
                    # Example of extracting features (in a real scenario, you'd extract more)
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    proto = packet[IP].proto
                    length = len(packet)
                    timestamp = time.time()
                    
                    # Store packet info
                    self.packets.append({
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'proto': proto,
                        'length': length
                    })
                    
                    # If we have enough packets, extract flow features
                    if len(self.packets) >= PACKET_BUFFER_SIZE:
                        self.extract_flow_features()
                        return True
            
            return False
        
        except Exception as e:
            logger.error(f"Erreur lors du traitement du paquet: {str(e)}")
            return False
    
    def extract_flow_features(self):
        """Extract flow features from collected packets"""
        if not self.packets:
            return None
            
        try:
            # This is a simplified version - in a real scenario, you'd compute actual network flow metrics
            # Group packets by flow (src_ip, dst_ip, proto)
            flows = {}
            for p in self.packets:
                flow_key = (p['src_ip'], p['dst_ip'], p['proto'])
                if flow_key not in flows:
                    flows[flow_key] = []
                flows[flow_key].append(p)
            
            flow_features = []
            
            # Extract features for each flow
            for (src, dst, proto), packets in flows.items():
                if len(packets) < 2:  # Need at least 2 packets for a meaningful flow
                    continue
                    
                # Sort by timestamp
                packets.sort(key=lambda x: x['timestamp'])
                
                # Calculate basic flow features
                flow_duration = packets[-1]['timestamp'] - packets[0]['timestamp']
                if flow_duration == 0:
                    flow_duration = 0.001  # Avoid division by zero
                    
                # Count packets in each direction
                fwd_packets = sum(1 for p in packets if p['src_ip'] == src)
                bwd_packets = len(packets) - fwd_packets
                
                # Calculate packet lengths
                fwd_lengths = [p['length'] for p in packets if p['src_ip'] == src]
                bwd_lengths = [p['length'] for p in packets if p['src_ip'] != src]
                
                total_fwd_length = sum(fwd_lengths) if fwd_lengths else 0
                total_bwd_length = sum(bwd_lengths) if bwd_lengths else 0
                
                # Create a feature dictionary mapping to our model's expected features
                # This is simplified - you'll need to adapt to your actual feature set
                feature_dict = {
                    "Flow Duration": flow_duration,
                    "Total Fwd Packets": fwd_packets,
                    "Total Backward Packets": bwd_packets,
                    "Total Length of Fwd Packets": total_fwd_length,
                    "Total Length of Bwd Packets": total_bwd_length,
                    "Flow Bytes/s": (total_fwd_length + total_bwd_length) / flow_duration,
                    "Flow Packets/s": len(packets) / flow_duration,
                    "Fwd Packets/s": fwd_packets / flow_duration if fwd_packets > 0 else 0,
                    "Bwd Packets/s": bwd_packets / flow_duration if bwd_packets > 0 else 0,
                    "Down/Up Ratio": total_bwd_length / total_fwd_length if total_fwd_length > 0 else 0,
                }
                
                # Add all required features with default values
                for feature in self.feature_names:
                    if feature not in feature_dict:
                        feature_dict[feature] = 0
                
                flow_features.append(feature_dict)
            
            # Clear packet buffer
            self.packets = []
            
            if flow_features:
                return pd.DataFrame(flow_features)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques: {str(e)}")
            return None

def packet_capture_thread(processor):
    """Thread function to capture packets"""
    try:
        logger.info("Démarrage de la capture de paquets...")
        
        # For testing, generate simulated packets instead of actual sniffing
        while True:
            # In a real scenario, replace this with actual packet capture:
            # sniff(prn=processor.process_packet, store=0, count=10)
            
            # Generate a simulated packet
            simulated_packet = {
                IP: type('obj', (object,), {
                    'src': f"192.168.1.{np.random.randint(1, 255)}",
                    'dst': f"10.0.0.{np.random.randint(1, 255)}",
                    'proto': np.random.choice([6, 17])  # TCP or UDP
                })
            }
            
            # Process the simulated packet
            processor.process_packet(simulated_packet)
            
            # Sleep briefly to avoid high CPU usage
            time.sleep(0.05)
    
    except KeyboardInterrupt:
        logger.info("Capture de paquets arrêtée")
    except Exception as e:
        logger.error(f"Erreur dans la capture de paquets: {str(e)}")
        logger.error(traceback.format_exc())

def generate_sample_traffic():
    """Generate sample network traffic data for testing"""
    # Read the features from the file
    if not os.path.exists(FEATURES_PATH):
        logger.error(f"Liste de caractéristiques introuvable : {FEATURES_PATH}")
        return None
    
    with open(FEATURES_PATH, 'r') as f:
        features = [line.strip() for line in f.readlines()]
    
    # Generate 5 random data points
    data_points = []
    for _ in range(5):
        # Generate normal traffic (low probability of anomaly)
        if np.random.random() < 0.9:
            data_point = {feature: np.random.normal(0, 0.5) for feature in features}
        else:
            # Generate anomalous traffic (more extreme values)
            data_point = {feature: np.random.normal(0, 2.0) for feature in features}
        
        data_points.append(data_point)
    
    df = pd.DataFrame(data_points)
    return df

def realtime_detection_loop():
    """Main loop for real-time detection"""
    detector = AnomalyDetector()
    processor = PacketProcessor()
    last_viz_time = time.time()
    
    logger.info("Démarrage de la détection d'anomalies en temps réel...")
    logger.info(f"Intervalle de détection: {DETECTION_INTERVAL} secondes")
    
    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=packet_capture_thread, args=(processor,), daemon=True)
    capture_thread.start()
    
    try:
        while True:
            # Get traffic data (either from processor or generate sample)
            traffic_data = processor.extract_flow_features()
            
            if traffic_data is None or traffic_data.empty:
                # If no real traffic, generate sample data for testing
                traffic_data = generate_sample_traffic()
                
            if traffic_data is not None and not traffic_data.empty:
                # Run detection
                results, anomaly_count = detector.detect(traffic_data)
                
                # Print status
                status = "⚠️ ANOMALIE DÉTECTÉE!" if anomaly_count > 0 else "✓ Trafic normal"
                logger.info(f"État: {status} | Total des alertes: {detector.alert_count}")
                
                # Update visualization periodically
                if time.time() - last_viz_time > 60:
                    detector.visualize_history()
                    last_viz_time = time.time()
            
            # Wait before next detection
            time.sleep(DETECTION_INTERVAL)
    
    except KeyboardInterrupt:
        logger.info("Détection arrêtée par l'utilisateur")
        detector.visualize_history()
    except Exception as e:
        logger.error(f"Erreur dans la boucle de détection: {str(e)}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    try:
        realtime_detection_loop()
    except Exception as e:
        logger.critical(f"Erreur critique: {str(e)}")
        logger.critical(traceback.format_exc())
