import pandas as pd
import numpy as np
import joblib
import os
import sys
import datetime
import traceback
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "../data")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "../models")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "../logs")
VISUALIZATIONS_DIR = os.path.join(os.path.dirname(__file__), "../visualizations")

# Create directories if they don't exist
for directory in [LOGS_DIR, VISUALIZATIONS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Paths
PROCESSED_DATA_PATH = os.path.join(DATA_DIR, "processed_data.csv")
MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_detector.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODELS_DIR, "features.txt")

def load_model_and_data():
    """Load the model and data for detection"""
    try:
        # Check if model exists
        if not os.path.exists(MODEL_PATH):
            print(f"ERREUR: Le modèle '{MODEL_PATH}' est introuvable. Lancez 'train_model.py' d'abord.")
            sys.exit(1)
        
        # Load model
        model = joblib.load(MODEL_PATH)
        print(f"\nModèle chargé depuis : {MODEL_PATH}")
        
        # Load features list if available
        features = []
        if os.path.exists(FEATURES_PATH):
            with open(FEATURES_PATH, "r") as f:
                features = [line.strip() for line in f.readlines()]
            print(f"Liste de {len(features)} caractéristiques chargée depuis {FEATURES_PATH}")
        
        # Load data
        if not os.path.exists(PROCESSED_DATA_PATH):
            print(f"ERREUR: Le fichier '{PROCESSED_DATA_PATH}' est introuvable. Lancez 'preprocess.py' d'abord.")
            sys.exit(1)
        
        data = pd.read_csv(PROCESSED_DATA_PATH)
        if data.empty:
            print(f"ERREUR: Le fichier '{PROCESSED_DATA_PATH}' est vide.")
            sys.exit(1)
            
        print(f"Données chargées depuis : {PROCESSED_DATA_PATH}")
        print(f"Forme des données: {data.shape}")
        
        return model, data, features
        
    except Exception as e:
        print(f"ERREUR lors du chargement du modèle ou des données: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

def align_features(data, features):
    """Ensure data has the expected features in the expected order"""
    if not features:
        return data  # No feature list to align with
        
    # Check for missing features
    missing_features = [f for f in features if f not in data.columns]
    if missing_features:
        print(f"Ajout des caractéristiques manquantes: {missing_features}")
        for feat in missing_features:
            data[feat] = 0  # Default value
    
    # Check for extra features
    extra_features = [f for f in data.columns if f not in features and f not in ['anomaly', 'anomaly_score', 'Label']]
    if extra_features:
        print(f"Suppression des caractéristiques non utilisées par le modèle: {extra_features}")
        data = data.drop(columns=extra_features)
    
    # Ensure proper order
    if features:
        # Keep special columns like 'Label' if they exist
        special_cols = [col for col in data.columns if col not in features]
        data = data[features + special_cols]
    
    return data

def detect_anomalies(model, data):
    """Detect anomalies in the provided data"""
    try:
        # Get features only (exclude any labels or results columns)
        exclude_cols = ['anomaly', 'anomaly_score', 'Label', 'Prediction']
        feature_cols = [col for col in data.columns if col not in exclude_cols]
        X = data[feature_cols]
        
        # Make predictions
        print("\nDétection des anomalies...")
        predictions = model.predict(X)
        scores = model.decision_function(X)
        
        # Convert to readable format (1 for anomaly, 0 for normal)
        anomalies = np.where(predictions == -1, 1, 0)
        
        # Add results to DataFrame
        data['anomaly'] = anomalies
        data['anomaly_score'] = scores
        
        # Count anomalies
        anomaly_count = anomalies.sum()
        normal_count = len(anomalies) - anomaly_count
        
        print("\nRésultats de la détection:")
        print(f"  - Trafic normal: {normal_count} ({normal_count/len(data)*100:.2f}%)")
        print(f"  - Anomalies détectées: {anomaly_count} ({anomaly_count/len(data)*100:.2f}%)")
        
        return data
        
    except Exception as e:
        print(f"ERREUR lors de la détection des anomalies: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

def save_results(results):
    """Save detection results to files"""
    try:
        # Create timestamp for filenames
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save full results
        results_path = os.path.join(LOGS_DIR, f"detection_results_{timestamp}.csv")
        results.to_csv(results_path, index=False)
        print(f"\nRésultats complets sauvegardés dans: {results_path}")
        
        # Save anomalies only
        if 'anomaly' in results.columns and results['anomaly'].sum() > 0:
            anomalies = results[results['anomaly'] == 1]
            anomalies_path = os.path.join(LOGS_DIR, f"anomalies_{timestamp}.csv")
            anomalies.to_csv(anomalies_path, index=False)
            print(f"Anomalies sauvegardées dans: {anomalies_path}")
        
        # Save standard results file (overwrite existing)
        standard_path = os.path.join(DATA_DIR, "detection_results.csv")
        results.to_csv(standard_path, index=False)
        
        return results_path
        
    except Exception as e:
        print(f"ERREUR lors de la sauvegarde des résultats: {str(e)}")
        return None

def visualize_results(results, output_dir=VISUALIZATIONS_DIR):
    """Create visualizations of detection results"""
    try:
        if 'anomaly' not in results.columns:
            print("Impossible de créer des visualisations: colonne 'anomaly' manquante")
            return
            
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Distribution of anomaly scores
        plt.figure(figsize=(10, 6))
        plt.hist(results['anomaly_score'], bins=30, color='skyblue', edgecolor='black')
        plt.axvline(x=0, color='red', linestyle='--', alpha=0.7)
        plt.title('Distribution des scores d\'anomalie')
        plt.xlabel('Score d\'anomalie')
        plt.ylabel('Nombre de flux')
        plt.grid(True, alpha=0.3)
        score_dist_path = os.path.join(output_dir, f"score_distribution_{timestamp}.png")
        plt.savefig(score_dist_path)
        plt.close()
        
        # 2. Feature comparison for normal vs anomalous traffic
        if len(results['anomaly'].unique()) > 1:  # Only if we have both normal and anomalous
            # Select important numeric features
            numeric_cols = results.select_dtypes(include=np.number).columns.tolist()
            features_to_plot = [col for col in numeric_cols if col not in ['anomaly', 'anomaly_score']]
            
            # If too many features, select a subset
            if len(features_to_plot) > 8:
                features_to_plot = features_to_plot[:8]
            
            # Create a copy of results with anomaly as string for visualization
            vis_data = results.copy()
            vis_data['anomaly_type'] = vis_data['anomaly'].map({0: 'Normal', 1: 'Anomalie'})
            
            # Create boxplots instead of violinplots (more reliable with legend)
            fig, axes = plt.subplots(2, 4, figsize=(16, 10))
            axes = axes.flatten()
            
            for i, feature in enumerate(features_to_plot[:8]):
                # Fix the deprecation warning by using hue instead of x
                sns.boxplot(y=feature, hue='anomaly_type', data=vis_data, 
                           palette={'Normal': 'skyblue', 'Anomalie': 'salmon'}, 
                           ax=axes[i])
                axes[i].set_title(feature)
                axes[i].set_xlabel('')
                
            plt.tight_layout()
            features_path = os.path.join(output_dir, f"feature_comparison_{timestamp}.png")
            plt.savefig(features_path)
            plt.close()
            
            # 3. Add a summary plot showing the most important features
            if len(features_to_plot) > 2:
                plt.figure(figsize=(12, 8))
                
                # Select top features that might be most interesting
                top_features = features_to_plot[:3]
                
                # Create a scatter plot of the top 2 features
                plt.subplot(2, 1, 1)
                scatter = plt.scatter(
                    results[top_features[0]], 
                    results[top_features[1]],
                    c=results['anomaly'], 
                    cmap=plt.cm.coolwarm,
                    alpha=0.7,
                    s=80
                )
                plt.xlabel(top_features[0])
                plt.ylabel(top_features[1])
                plt.title(f"Anomalies détectées ({top_features[0]} vs {top_features[1]})")
                
                # Fix the mixed positional and keyword arguments warning
                legend_elements = scatter.legend_elements()
                legend = plt.legend(legend_elements[0], ["Normal", "Anomalie"], title="Classification")
                
                # Create a 3rd feature visualization - fix the deprecation warning
                plt.subplot(2, 1, 2)
                sns.barplot(y=top_features[2], hue='anomaly_type', data=vis_data, 
                           palette={'Normal': 'skyblue', 'Anomalie': 'salmon'})
                plt.title(f"Comparaison de {top_features[2]} entre trafic normal et anomalies")
                plt.xlabel("Type de trafic")
                
                plt.tight_layout()
                summary_path = os.path.join(output_dir, f"anomalies_summary_{timestamp}.png")
                plt.savefig(summary_path)
                plt.close()
        
        print(f"\nVisualisations sauvegardées dans: {output_dir}")
        
    except Exception as e:
        print(f"ERREUR lors de la création des visualisations: {str(e)}")
        traceback.print_exc()

def main():
    """Main function for anomaly detection"""
    print("\n=== Détection d'Anomalies - IDS Cyber-IA ===\n")
    
    try:
        # Load model and data
        model, data, features = load_model_and_data()
        
        # Align features if needed
        data = align_features(data, features)
        
        # Detect anomalies
        results = detect_anomalies(model, data)
        
        # Save results
        results_path = save_results(results)
        
        # Create visualizations
        visualize_results(results)
        
        print("\nDétection terminée avec succès!")
        
    except Exception as e:
        print(f"\nERREUR CRITIQUE: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()