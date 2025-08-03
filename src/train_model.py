import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "../data")
PROCESSED_DATA_PATH = os.path.join(DATA_DIR, "processed_data.csv")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "../models")
MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_detector.pkl")

# --- New Configuration ---
DEFAULT_CONTAMINATION = 0.1


def train_anomaly_detection_model(contamination=DEFAULT_CONTAMINATION):
    """
    Train an anomaly detection model on the preprocessed data
    """
    # Vérifier que les données prétraitées existent
    if not os.path.exists(PROCESSED_DATA_PATH):
        raise FileNotFoundError(f"Le fichier '{PROCESSED_DATA_PATH}' est introuvable. Lancez 'preprocess.py' d'abord.")

    print(f"Chargement des données prétraitées depuis '{PROCESSED_DATA_PATH}'...")
    df = pd.read_csv(PROCESSED_DATA_PATH)
    
    # Afficher des statistiques sur les données
    print(f"Forme des données: {df.shape}")
    print("\nStatistiques descriptives:")
    print(df.describe().T)
    
    # Séparer les features (toutes les colonnes)
    X = df.values
    
    print("\nEntraînement du modèle de détection d'anomalies (Isolation Forest)...")
    # Isolation Forest est un bon algorithme pour la détection d'anomalies
    # contamination=0.1 signifie que nous supposons qu'environ 10% des données sont des anomalies
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X)
    
    # Prédire les anomalies (-1 pour anomalie, 1 pour normal)
    predictions = model.predict(X)
    anomaly_scores = model.decision_function(X)
    
    # Convertir les prédictions en format plus lisible (1 pour anomalie, 0 pour normal)
    anomalies = np.where(predictions == -1, 1, 0)
    
    # Ajouter les résultats au DataFrame original
    df_results = df.copy()
    df_results['anomaly'] = anomalies
    df_results['anomaly_score'] = anomaly_scores
    
    # Sauvegarder le modèle
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Modèle sauvegardé dans '{MODEL_PATH}'")
    
    # Analyser les résultats
    n_anomalies = anomalies.sum()
    print(f"\nRésultats de la détection:")
    print(f"  - Nombre d'anomalies détectées: {n_anomalies} ({n_anomalies/len(df)*100:.2f}%)")
    print(f"  - Nombre d'instances normales: {len(df) - n_anomalies}")
    
    # Sauvegarder les résultats avec les anomalies étiquetées
    results_path = os.path.join(DATA_DIR, "detection_results.csv")
    df_results.to_csv(results_path, index=False)
    print(f"Résultats sauvegardés dans '{results_path}'")
    
    return df_results

def visualize_results(df_results):
    """
    Créer des visualisations pour comprendre les anomalies détectées
    """
    print("\nCréation des visualisations...")
    
    # Créer un dossier pour les visualisations
    vis_dir = os.path.join(os.path.dirname(__file__), "../visualizations")
    os.makedirs(vis_dir, exist_ok=True)
    
    # 1. Distribution des scores d'anomalie
    plt.figure(figsize=(10, 6))
    plt.hist(df_results['anomaly_score'], bins=30, alpha=0.7)
    plt.axvline(x=0, color='red', linestyle='--', alpha=0.5)
    plt.xlabel('Score d\'anomalie')
    plt.ylabel('Nombre d\'instances')
    plt.title('Distribution des scores d\'anomalie')
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(vis_dir, 'anomaly_score_distribution.png'))
    
    # 2. Visualiser les caractéristiques des anomalies vs normales
    # Sélectionner quelques features importantes pour la visualisation
    selected_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
                         'Flow Bytes/s', 'Flow Packets/s']
    
    # Créer un dataframe pour la visualisation
    df_vis = df_results[selected_features + ['anomaly']].copy()
    df_vis['anomaly'] = df_vis['anomaly'].map({1: 'Anomalie', 0: 'Normal'})
    
    # Créer des pairplots pour visualiser les relations entre les caractéristiques
    plt.figure(figsize=(12, 10))
    sns.pairplot(df_vis, hue='anomaly', palette={'Normal': 'blue', 'Anomalie': 'red'})
    plt.suptitle('Relations entre caractéristiques selon les anomalies', y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(vis_dir, 'feature_relationships.png'))
    
    print(f"Visualisations sauvegardées dans '{vis_dir}'")

if __name__ == "__main__":
    try:
        # Entraîner le modèle et obtenir les résultats
        results = train_anomaly_detection_model()
        
        # Créer des visualisations
        visualize_results(results)
        
        print("\nProcessus terminé avec succès!")
    except FileNotFoundError as e:
        print(f"ERREUR: {e}")
    except Exception as e:
        print(f"Une erreur inattendue est survenue: {e}")
