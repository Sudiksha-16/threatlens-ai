import joblib, json, numpy as np, pandas as pd, warnings
warnings.filterwarnings('ignore')

scaler = joblib.load('backend/app/ml/preprocessing/binary_scaler.joblib')
model = joblib.load('backend/app/ml/saved_models/active_binary_model.joblib')
with open('backend/app/ml/preprocessing/binary_features.json') as f:
    features = json.load(f)

# Load and test on actual training test data
X_test = np.load('training/processed/binary_X_test.npy')
y_test = np.load('training/processed/binary_y_test.npy')
print('Test data shape:', X_test.shape)
print('Test labels distribution:', dict(zip(*np.unique(y_test, return_counts=True))))

# Transform test data
X_test_df = pd.DataFrame(X_test, columns=features)
X_test_scaled = scaler.transform(X_test_df)
preds = model.predict(X_test_scaled)
print('Model predictions distribution on test set:', dict(zip(*np.unique(preds, return_counts=True))))
from sklearn.metrics import accuracy_score
print('Accuracy on test set:', accuracy_score(y_test, preds))

# Check what zero input looks like after scaling
zeros_df = pd.DataFrame([[0.0]*69], columns=features)
scaled = scaler.transform(zeros_df)
print('\nZero input after scaling:', scaled[0][:10], '...')
print('Zero vector mean values:', scaler.mean_[:5], '...')
print('Zero vector scale values:', scaler.scale_[:5], '...')

# The zero vector after scaling = (0 - mean) / std -> negative means data is typically positive
# If mean is large (most features > 0 for real files), then a zero input = extreme negative values

# Let's check a few sample rows from training data
print('\nFirst 3 rows of X_test:')
print(X_test[:3])
print('\nFirst 3 labels:', y_test[:3])
