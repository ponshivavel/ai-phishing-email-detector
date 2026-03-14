import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.pipeline import Pipeline
import pickle
from src.utils import clean_email
import warnings
warnings.filterwarnings('ignore')

print("=== Enhanced Phishing Model Training ===")

# Load FULL dataset (remove nrows limit for better training)
print("Loading dataset...")
df = pd.read_csv("data/phishing_email.csv")
print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['label'].value_counts()}")

# 1. PREPROCESSING: Apply NLP pipeline to ALL text
print("\n1. Applying NLP preprocessing...")
df['text_clean'] = df['text_combined'].apply(clean_email)
print("✅ Preprocessing complete")

# 2. Train/Test Split
X = df['text_clean']
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 3. TF-IDF Vectorizer (KEEP COMPATIBLE: max_features=5000)
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000, ngram_range=(1,2))

print("\n2. Training models...")

# BASELINE: Logistic Regression
lr_pipeline = Pipeline([
    ('tfidf', vectorizer),
    ('classifier', LogisticRegression(max_iter=1000, random_state=42))
])
lr_pipeline.fit(X_train, y_train)
lr_pred = lr_pipeline.predict(X_test)
lr_f1 = f1_score(y_test, lr_pred)

print("Logistic Regression - F1:", round(lr_f1, 4))

# IMPROVED: Random Forest
rf_pipeline = Pipeline([
    ('tfidf', vectorizer),  # Same vectorizer for compatibility
    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
])
rf_pipeline.fit(X_train, y_train)
rf_pred = rf_pipeline.predict(X_test)
rf_f1 = f1_score(y_test, rf_pred)

print("Random Forest - F1:", round(rf_f1, 4))

# 4. SELECT BEST MODEL (F1-score)
if rf_f1 > lr_f1:
    best_model = rf_pipeline
    best_name = "Random Forest"
    print(f"\n✅ Selected {best_name} (F1: {rf_f1:.4f} > {lr_f1:.4f})")
else:
    best_model = lr_pipeline
    best_name = "Logistic Regression"
    print(f"\n✅ Selected {best_name} (F1: {lr_f1:.4f} >= {rf_f1:.4f})")

# 5. Full Metrics for Best Model
best_pred = best_model.predict(X_test)
print(f"\n{best_name} Full Metrics:")
print(f"Accuracy: {accuracy_score(y_test, best_pred):.4f}")
print(f"Precision: {precision_score(y_test, best_pred):.4f}")
print(f"Recall: {recall_score(y_test, best_pred):.4f}")
print(f"F1-Score: {f1_score(y_test, best_pred):.4f}")

# 6. BACKWARD COMPATIBLE: Save vectorizer + model (app.py expects this format)
print("\n3. Saving compatible artifacts...")
with open("model/phishing_model.pkl", "wb") as f:
    pickle.dump(best_model.named_steps['classifier'], f)  # Save classifier only
with open("model/vectorizer.pkl", "wb") as f:
    pickle.dump(best_model.named_steps['tfidf'], f)

print("✅ Training complete! Model + Vectorizer saved (backward compatible)")
print("✅ app.py will work without changes")


