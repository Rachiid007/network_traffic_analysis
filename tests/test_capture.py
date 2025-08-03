import unittest
import pandas as pd
import os

class TestCapture(unittest.TestCase):
    """Tests pour la capture de trafic réseau."""

    def setUp(self):
        """Définir le chemin du fichier de données."""
        self.raw_data_path="../data/raw_data.csv"

    def test_file_exists(self):
        """Vérifie si le fichier raw_data.csv existe après la capture."""
        self.assertTrue(os.path.exists(self.raw_data_path), "Le fichier raw_data.csv n'existe pas.")

    def test_file_not_empty(self):
        """Vérifie si raw_data.csv contient des données."""
        df=pd.read_csv(self.raw_data_path)
        self.assertFalse(df.empty, "Le fichier raw_data.csv est vide.")

if __name__=="__main__":
    unittest.main()