import unittest
import pandas as pd
import os

class TestPreprocessing(unittest.TestCase):
    """Tests pour le prétraitement des données."""

    def setUp(self):
        """Définir le chemin du fichier de données."""
        self.processed_data_path=os.path.join(os.path.dirname(__file__), "../data/processed_data.csv")

    def test_file_exists(self):
        """Vérifie si le fichier processed_data.csv existe après le prétraitement."""
        self.assertTrue(os.path.exists(self.processed_data_path), "Le fichier processed_data.csv n'existe pas")

    def test_file_not_empty(self):
        """Vérifie si processed_data.csv contient des données."""
        if not os.path.exists(self.processed_data_path):
            self.skipTest("Le fichier processed_data.csv est manquant, impossible de tester.")
        df=pd.read_csv(self.processed_data_path)
        self.assertFalse(df.empty, "Le fichier processed_data.csv est vide")

    def test_columns_exist(self):
        """Vérifie si les colonnes essentielles existent."""
        if not os.path.exists(self.processed_data_path):
            self.skipTest("Le fichier processed_data.csv est manquant, impossible de tester.")
        df= pd.read_csv(self.processed_data_path)
        required_columns = {"src_ip", "dst_ip", "protocol", "length", "src_port", "dst_port", "protocol_name"}
        self.assertTrue(required_columns.issubset(df.columns), " Une ou plusieurs colonnes essentielles sont absentes.")

if __name__=="__main__":
    unittest.main()
