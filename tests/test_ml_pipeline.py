import os
import unittest
import numpy as np
from backend.app.services.ml_engine import ml_engine
from backend.app.services.feature_engineering import feature_engineer

class TestMLPipeline(unittest.TestCase):
    def test_ml_engine_loaded(self):
        self.assertTrue(ml_engine.is_loaded)
        self.assertIsNotNone(ml_engine.active_model)

    def test_feature_engineering_vector_shape(self):
        dummy_static = {
            "file_size": 256000,
            "entropy": 6.45,
            "is_pe": False
        }
        vec = feature_engineer.extract_feature_vector(dummy_static)
        self.assertEqual(vec.shape, (1, 69))

    def test_prediction_output_format(self):
        dummy_static = {
            "file_size": 150000,
            "entropy": 5.12,
            "is_pe": False
        }
        pred = ml_engine.predict(dummy_static)
        self.assertIsNotNone(pred)
        self.assertIn("classification", pred)
        self.assertIn("confidence", pred)
        self.assertIn("class_probabilities", pred)
        self.assertIn("model_name", pred)
        self.assertIn("Benign", pred["class_probabilities"])
        self.assertIn("Malicious", pred["class_probabilities"])
        self.assertAlmostEqual(
            pred["class_probabilities"]["Benign"] + pred["class_probabilities"]["Malicious"],
            1.0,
            places=2
        )

if __name__ == "__main__":
    unittest.main()
