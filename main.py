from preprocess import PhishingDataPreprocessor
from model import EnsembleClassifier
from gui import PhishingDetectorGUI

if __name__ == "__main__":
    # Preprocess data
    preprocessor = PhishingDataPreprocessor()
    preprocessor.preprocess()

    # Train model
    classifier = EnsembleClassifier()
    classifier.run_training_pipeline()

    # Run GUI
    gui = PhishingDetectorGUI()
    gui.run()