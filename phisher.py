import os
import logging
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# Set up clean output logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# =====================================================================
# 1. CUSTOM FEATURE EXTRACTION TRANSFORMERS
# =====================================================================

class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts numerical metadata features from email body content.
    Identifies URL density, IP-based URLs, urgent keywords, and formatting.
    """
    def __init__(self):
        self.phishing_keywords = {
            'urgent', 'locked', 'verify', 'account', 'password', 
            'update', 'bank', 'action', 'alert', 'claim', 'login', 'security'
        }

    def fit(self, X, y=None):
        return self

    def _analyze_single_text(self, text):
        words = text.lower().split()
        
        # Check for URL structures and IP presence
        urls = [word for word in words if word.startswith(('http://', 'https://', 'www.'))]
        url_count = len(urls)
        
        has_ip = 0
        for url in urls:
            domain = urlparse(url).netloc
            # Check if domain consists of an IP structure
            parts = domain.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p):
                has_ip = 1
                break

        # Calculate keyword presence and formatting traits
        urgent_count = sum(1 for word in words if word.strip("!.,?:;") in self.phishing_keywords)
        exclamation_count = text.count('!')
        char_length = len(text)
        word_count = len(words)
        
        return [url_count, has_ip, urgent_count, exclamation_count, char_length, word_count]

    def transform(self, X):
        features = [self._analyze_single_text(text) for text in X]
        return np.array(features)


# =====================================================================
# 2. DATA PREPARATION & SYNTHETIC BENCHMARK
# =====================================================================

def load_dataset():
    """
    Generates a realistic baseline dataset. Replace this loader with:
    `df = pd.read_csv('your_email_dataset.csv')`
    """
    data = [
        # Phishing Examples
        ("URGENT: Your online banking access has been restricted. Visit http://192.168.0.1/verify to unlock.", "Phishing"),
        ("Final Notice: You have 1 unread security alert. Update password now at http://secure-login-portal.com", "Phishing"),
        ("You have won a $500 gift card! Click here to claim your reward: http://bit.ly/claim-reward-now", "Phishing"),
        ("Suspicious activity detected on your PayPal account. Please log in immediately: http://paypal-security-check.org", "Phishing"),
        ("Account Notice: Verify your email address to prevent service suspension. http://service-update-center.net", "Phishing"),
        
        # Safe Examples
        ("Hi team, please review the attached agenda for tomorrow's strategy alignment meeting.", "Safe"),
        ("The quarterly financial report is finalized. Let me know if you need any adjustments.", "Safe"),
        ("Reminder: Team lunch is scheduled for Friday at 12:30 PM at the main cafeteria.", "Safe"),
        ("Can you send over the updated slides for the project presentation by end of day?", "Safe"),
        ("Thanks for the quick call earlier. I have updated the Jira ticket with our notes.", "Safe")
    ]
    
    return pd.DataFrame(data, columns=['text', 'label'])


# =====================================================================
# 3. PIPELINE IMPLEMENTATION & TRAINING
# =====================================================================

def main():
    logging.info("Loading email dataset...")
    df = load_dataset()
    
    X = df['text']
    y = df['label'].map({'Safe': 0, 'Phishing': 1})

    # Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    logging.info("Extracting textual and structural features...")
    
    # Feature 1: Numerical/Structural Metadata
    structural_extractor = StructuralFeatureExtractor()
    
    # Feature 2: Textual TF-IDF Matrix
    tfidf_vectorizer = TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_features=500
    )

    # Process training data
    X_train_struct = structural_extractor.transform(X_train)
    X_train_tfidf = tfidf_vectorizer.fit_transform(X_train).toarray()
    
    # Combine features into single feature matrix
    X_train_full = np.hstack((X_train_struct, X_train_tfidf))

    # Process testing data
    X_test_struct = structural_extractor.transform(X_test)
    X_test_tfidf = tfidf_vectorizer.transform(X_test).toarray()
    X_test_full = np.hstack((X_test_struct, X_test_tfidf))

    # Model Initialization & Training
    logging.info("Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        random_state=42
    )
    model.fit(X_train_full, y_train)

    # =====================================================================
    # 4. EVALUATION & METRICS DISPLAY
    # =====================================================================
    predictions = model.predict(X_test_full)
    accuracy = accuracy_score(y_test, predictions)
    
    print("\n" + "="*50)
    print(f"MODEL ACCURACY: {accuracy * 100:.2f}%")
    print("="*50 + "\n")
    
    print("Classification Report:")
    print(classification_report(y_test, predictions, target_names=['Safe', 'Phishing']))

    # Generate Confusion Matrix Visualization
    cm = confusion_matrix(y_test, predictions)
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm, 
        annot=True, 
        fmt='d', 
        cmap='Blues', 
        xticklabels=['Safe', 'Phishing'], 
        yticklabels=['Safe', 'Phishing']
    )
    plt.title("Phishing Detection - Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()