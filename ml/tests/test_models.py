import unittest
import numpy as np
import pandas as pd
from app.models.threat_detection import ThreatDetectionModel
from app.models.vulnerability_assessment import VulnerabilityAssessmentModel


class TestThreatDetectionModel(unittest.TestCase):
    def setUp(self):
        self.model = ThreatDetectionModel()
        # Create sample data for testing
        self.sample_data = {
            'source_ip': ['192.168.1.1', '10.0.0.1'],
            'destination_ip': ['10.0.0.2', '192.168.1.2'],
            'source_port': [12345, 54321],
            'destination_port': [80, 443],
            'protocol': ['TCP', 'UDP'],
            'packet_count': [100, 200],
            'byte_count': [1500, 3000],
            'duration': [5.2, 10.5],
            'flag_syn': [1, 0],
            'flag_ack': [0, 1],
            'flag_fin': [0, 0]
        }
        self.sample_labels = ['benign', 'malicious']

    def test_preprocess_features(self):
        # Test preprocessing of features
        df = pd.DataFrame(self.sample_data)
        processed_features = self.model.preprocess_features(df)
        
        # Check that the output is a numpy array
        self.assertIsInstance(processed_features, np.ndarray)
        
        # Check that all features were processed
        self.assertEqual(processed_features.shape[0], 2)  # 2 samples

    def test_train_and_predict(self):
        # Test training and prediction
        df = pd.DataFrame(self.sample_data)
        labels = np.array(self.sample_labels)
        
        # Train the model
        self.model.train(df, labels)
        
        # Make predictions
        predictions = self.model.predict(df)
        probabilities = self.model.predict_proba(df)
        
        # Check predictions format
        self.assertEqual(len(predictions), 2)
        self.assertEqual(len(probabilities), 2)
        
        # Check that probabilities are between 0 and 1
        self.assertTrue(all(0 <= p <= 1 for p in probabilities))

    def test_save_and_load(self):
        # Test saving and loading the model
        df = pd.DataFrame(self.sample_data)
        labels = np.array(self.sample_labels)
        
        # Train the model
        self.model.train(df, labels)
        
        # Save the model
        model_path = '/tmp/threat_detection_test.joblib'
        self.model.save(model_path)
        
        # Load the model
        new_model = ThreatDetectionModel()
        new_model.load(model_path)
        
        # Check that the loaded model can make predictions
        predictions = new_model.predict(df)
        self.assertEqual(len(predictions), 2)


class TestVulnerabilityAssessmentModel(unittest.TestCase):
    def setUp(self):
        self.model = VulnerabilityAssessmentModel()
        # Create sample data for testing
        self.sample_data = {
            'cve_id': ['CVE-2021-1234', 'CVE-2022-5678'],
            'cwe_id': ['CWE-79', 'CWE-89'],
            'cvss_base_score': [7.5, 9.1],
            'access_vector': ['NETWORK', 'LOCAL'],
            'access_complexity': ['LOW', 'HIGH'],
            'authentication': ['NONE', 'SINGLE'],
            'confidentiality_impact': ['PARTIAL', 'COMPLETE'],
            'integrity_impact': ['PARTIAL', 'COMPLETE'],
            'availability_impact': ['PARTIAL', 'COMPLETE'],
            'patch_available': [1, 0],
            'exploit_available': [0, 1]
        }
        self.sample_scores = [6.5, 8.9]

    def test_preprocess_features(self):
        # Test preprocessing of features
        df = pd.DataFrame(self.sample_data)
        processed_features = self.model.preprocess_features(df)
        
        # Check that the output is a numpy array
        self.assertIsInstance(processed_features, np.ndarray)
        
        # Check that all features were processed
        self.assertEqual(processed_features.shape[0], 2)  # 2 samples

    def test_train_and_predict(self):
        # Test training and prediction
        df = pd.DataFrame(self.sample_data)
        scores = np.array(self.sample_scores)
        
        # Train the model
        self.model.train(df, scores)
        
        # Make predictions
        predictions = self.model.predict(df)
        severities = self.model.get_severity(predictions)
        
        # Check predictions format
        self.assertEqual(len(predictions), 2)
        self.assertEqual(len(severities), 2)
        
        # Check that severities are valid
        valid_severities = ['low', 'medium', 'high', 'critical']
        for severity in severities:
            self.assertIn(severity, valid_severities)

    def test_save_and_load(self):
        # Test saving and loading the model
        df = pd.DataFrame(self.sample_data)
        scores = np.array(self.sample_scores)
        
        # Train the model
        self.model.train(df, scores)
        
        # Save the model
        model_path = '/tmp/vulnerability_assessment_test.joblib'
        self.model.save(model_path)
        
        # Load the model
        new_model = VulnerabilityAssessmentModel()
        new_model.load(model_path)
        
        # Check that the loaded model can make predictions
        predictions = new_model.predict(df)
        self.assertEqual(len(predictions), 2)


if __name__ == '__main__':
    unittest.main()