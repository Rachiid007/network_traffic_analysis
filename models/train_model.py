import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler
import yaml

# --- Configuration ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")

def load_config():
    """Charge la configuration depuis un fichier YAML."""
    default_config = {
        'paths': {
            'data_dir': '../data',
            'dataset': 'processed_data.csv',
            'model': 'trained_model.pkl',
            'features': 'features.txt',
            'logs_dir': '../logs'
        },
        'model_params': {
            'test_size': 0.25,
            'random_state': 42,
            'class_weight': 'balanced'
        },
        'hyperparam_tuning': {
            'enabled': False,
            'param_grid': {
                'n_estimators': [100, 200],
                'max_depth': [10, 20, None],
                'min_samples_leaf': [1, 2, 4]
            },
            'cv': 3,
            'scoring': 'f1_weighted'
        }
    }
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        return default_config
    
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

def main():
    """Fonction principale pour l'entraînement du modèle."""
    config = load_config()
    paths = config['paths']
    model_params = config['model_params']
    tuning_params = config['hyperparam_tuning']

    # Définition des chemins
    data_dir = os.path.join(os.path.dirname(__file__), paths['data_dir'])
    dataset_path = os.path.join(data_dir, paths['dataset'])
    model_path = os.path.join(os.path.dirname(__file__), paths['model'])
    features_path = os.path.join(os.path.dirname(__file__), paths['features'])
    logs_dir = os.path.join(os.path.dirname(__file__), paths['logs_dir'])

    try:
        # Chargement du dataset
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Le fichier '{dataset_path}' est introuvable. Lancez 'preprocess.py' d'abord.")

        df = pd.read_csv(dataset_path)
        print(f"\nDataset chargé. Dimensions: {df.shape}")
        print("Colonnes disponibles:", df.columns.tolist())

        # Vérification de la présence de la colonne 'Label'
        if 'Label' not in df.columns:
            raise ValueError("La colonne 'Label' est manquante. Un dataset étiqueté est requis pour l'entraînement supervisé.")

        # Sélection des caractéristiques (features)
        # Exclure les colonnes non-numériques et les identifiants si nécessaire
        features = [col for col in df.columns if col not in ['Label'] and np.issubdtype(df[col].dtype, np.number)]
        X = df[features]
        y = df["Label"]

        print(f"Nombre de caractéristiques utilisées: {len(features)}")
        print(f"Répartition des labels:\n{y.value_counts(normalize=True)}")

        # Remplacement des infinis et NaN
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        if X.isnull().sum().sum() > 0:
            print("Valeurs nulles détectées. Remplacement par la médiane de la colonne.")
            X.fillna(X.median(), inplace=True)

        # Mise à l'échelle des caractéristiques
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        X = pd.DataFrame(X_scaled, columns=features)

        # Séparation des données
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=model_params['test_size'], 
            random_state=model_params['random_state'],
            stratify=y  # Important pour les datasets déséquilibrés
        )

        # Entraînement du modèle
        if tuning_params['enabled']:
            print("\nRecherche des meilleurs hyperparamètres avec GridSearchCV...")
            rfc = RandomForestClassifier(random_state=model_params['random_state'], class_weight=model_params.get('class_weight'))
            grid_search = GridSearchCV(estimator=rfc, param_grid=tuning_params['param_grid'], 
                                       cv=tuning_params['cv'], scoring=tuning_params['scoring'], n_jobs=-1, verbose=2)
            grid_search.fit(X_train, y_train)
            model = grid_search.best_estimator_
            print(f"Meilleurs hyperparamètres trouvés: {grid_search.best_params_}")
        else:
            print("\nEntraînement du modèle Random Forest avec les paramètres par défaut...")
            model = RandomForestClassifier(
                n_estimators=100, 
                random_state=model_params['random_state'],
                class_weight=model_params.get('class_weight'),
                n_jobs=-1
            )
            model.fit(X_train, y_train)

        # Évaluation du modèle
        y_pred = model.predict(X_test)
        print("\nAccuracy:", accuracy_score(y_test, y_pred))
        print("F1-Score (pondéré):", f1_score(y_test, y_pred, average='weighted'))
        print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

        # Matrice de confusion
        plt.figure(figsize=(8, 6))
        sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt="d", cmap="Blues", 
                    xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
        plt.xlabel("Prédit")
        plt.ylabel("Réel")
        plt.title("Matrice de confusion")
        
        os.makedirs(logs_dir, exist_ok=True)
        plt.savefig(os.path.join(logs_dir, "confusion_matrix.png"))
        print(f"Matrice de confusion sauvegardée dans '{os.path.join(logs_dir, 'confusion_matrix.png')}'")

        # Sauvegarde du modèle et des composants
        pipeline = {
            'model': model,
            'scaler': scaler,
            'features': features
        }
        joblib.dump(pipeline, model_path)
        print(f"\nPipeline (modèle, scaler, features) sauvegardé dans : {model_path}")

        # Sauvegarde des caractéristiques (pour information)
        with open(features_path, "w") as f:
            f.write("\n".join(features))
        print(f"Liste des caractéristiques sauvegardée dans '{features_path}'")

    except FileNotFoundError as e:
        print(f"ERREUR: {e}")
    except ValueError as e:
        print(f"ERREUR de données: {e}")
    except Exception as e:
        print(f"Une erreur inattendue est survenue: {e}")

if __name__ == "__main__":
    main()
