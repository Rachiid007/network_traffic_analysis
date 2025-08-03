import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import StandardScaler
import joblib

# --- Configuration ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "../data")
RAW_DATA_PATH = os.path.join(DATA_DIR, "raw_data.csv")
PROCESSED_DATA_PATH = os.path.join(DATA_DIR, "processed_data.csv")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "../models/scaler.pkl")

def preprocess_data():
    """
    Charge les données brutes, les nettoie, les normalise et les sauvegarde.
    """
    if not os.path.exists(RAW_DATA_PATH):
        raise FileNotFoundError(f"Le fichier '{RAW_DATA_PATH}' est introuvable. Lancez 'capture.py' d'abord.")

    try:
        df = pd.read_csv(RAW_DATA_PATH)
    except pd.errors.EmptyDataError:
        raise ValueError("Le fichier de données brutes est vide. Aucune donnée à traiter.")

    print("Colonnes disponibles dans raw_data.csv :", df.columns.tolist())

    if df.empty:
        print("Le fichier de données est vide. Aucune action requise.")
        return

    print("Aperçu des données brutes :")
    print(df.head())

    # Vérifier et gérer les colonnes d'identification qui peuvent être absentes
    id_columns = ["src_ip", "dst_ip", "protocol_name"]
    available_id_columns = [col for col in id_columns if col in df.columns]
    
    # Créer df_ids seulement avec les colonnes disponibles + "Flow Start"
    if available_id_columns:
        df_ids = df[available_id_columns + ["Flow Start"]].copy()
        print(f"Colonnes d'identification extraites: {available_id_columns}")
    else:
        print("Aucune colonne d'identification trouvée (src_ip, dst_ip, protocol_name)")
        df_ids = df[["Flow Start"]].copy()

    # Définir les caractéristiques numériques à traiter
    numeric_features = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Flow IAT Mean", "Fwd IAT Mean", "Bwd IAT Mean",
        "Fwd Packets/s", "Bwd Packets/s",
        "SYN Flag Count", "ACK Flag Count", "PSH Flag Count", "FIN Flag Count",
        "Packet Length Mean", "Min Packet Length", "Max Packet Length",
        "Flow Bytes/s", "Flow Packets/s", "Down/Up Ratio"
    ]

    # S'assurer que toutes les colonnes attendues existent, sinon les ajouter avec 0
    for col in numeric_features:
        if col not in df.columns:
            print(f"Colonne manquante ajoutée : {col}")
            df[col] = 0

    # Sélectionner uniquement les caractéristiques numériques pour le traitement
    df_numeric = df[numeric_features].copy()

    # Remplacer les valeurs infinies par NaN, puis par la médiane de la colonne
    df_numeric.replace([np.inf, -np.inf], np.nan, inplace=True)
    if df_numeric.isnull().values.any():
        print("Remplacement des valeurs NaN par la médiane...")
        df_numeric.fillna(df_numeric.median(), inplace=True)

    # Normalisation avec StandardScaler
    print("Normalisation des données avec StandardScaler...")
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df_numeric)
    
    # Sauvegarder le scaler pour une utilisation future (pendant la détection)
    os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    print(f"Scaler sauvegardé dans '{SCALER_PATH}'")

    # Créer un nouveau DataFrame avec les données normalisées
    df_processed = pd.DataFrame(df_scaled, columns=numeric_features)

    # Ajouter une colonne 'Label' si elle existe dans les données brutes (pour l'entraînement)
    if 'Label' in df.columns:
        df_processed['Label'] = df['Label'].values

    # Sauvegarder les données traitées
    df_processed.to_csv(PROCESSED_DATA_PATH, index=False)

    print(f"Données prétraitées et normalisées sauvegardées dans '{PROCESSED_DATA_PATH}'")
    print("Aperçu des données traitées :")
    print(df_processed.head())

def test_preprocessing():
    """
    Test the preprocessing by verifying that output files exist and have valid content.
    """
    print("\n--- Testing Preprocessing Results ---")
    
    # Check if processed data file exists
    if not os.path.exists(PROCESSED_DATA_PATH):
        print(f"❌ Test failed: {PROCESSED_DATA_PATH} does not exist")
        return False
        
    # Check if scaler file exists
    if not os.path.exists(SCALER_PATH):
        print(f"❌ Test failed: {SCALER_PATH} does not exist")
        return False
    
    # Check if processed data has content
    try:
        processed_df = pd.read_csv(PROCESSED_DATA_PATH)
        if processed_df.empty:
            print(f"❌ Test failed: {PROCESSED_DATA_PATH} is empty")
            return False
        print(f"✅ {PROCESSED_DATA_PATH} exists with {len(processed_df)} rows")
    except Exception as e:
        print(f"❌ Test failed when reading processed data: {e}")
        return False
        
    # Check if scaler can be loaded
    try:
        loaded_scaler = joblib.load(SCALER_PATH)
        print(f"✅ {SCALER_PATH} loaded successfully")
    except Exception as e:
        print(f"❌ Test failed when loading scaler: {e}")
        return False
        
    print("✅ All preprocessing tests passed successfully")
    return True

if __name__ == "__main__":
    try:
        preprocess_data()
        # Run tests after preprocessing
        test_preprocessing()
    except (FileNotFoundError, ValueError) as e:
        print(f"ERREUR: {e}")
    except Exception as e:
        print(f"Une erreur inattendue est survenue: {e}")