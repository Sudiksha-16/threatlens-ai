import joblib, json, numpy as np, pandas as pd, warnings
warnings.filterwarnings('ignore')

scaler = joblib.load('backend/app/ml/preprocessing/binary_scaler.joblib')
model = joblib.load('backend/app/ml/saved_models/active_binary_model.joblib')
with open('backend/app/ml/preprocessing/binary_features.json') as f:
    features = json.load(f)

print('Feature names in scaler:', list(scaler.feature_names_in_)[:5], '...')
print('Feature names from json:', features[:5], '...')
print('Names match:', list(scaler.feature_names_in_) == features)

# Test with all zeros (what a non-PE file would give) - using DataFrame
zeros_df = pd.DataFrame([[0.0]*69], columns=features)
scaled_df = scaler.transform(zeros_df)
pred_df = model.predict(scaled_df)
prob_df = model.predict_proba(scaled_df)
print('ALL ZEROS (DataFrame) prediction:', pred_df[0], 'prob:', prob_df[0])

# Test with all zeros raw numpy (what current code does)
zeros_np = np.zeros((1, 69))
scaled_np = scaler.transform(zeros_np)
pred_np = model.predict(scaled_np)
prob_np = model.predict_proba(scaled_np)
print('ALL ZEROS (numpy) prediction:', pred_np[0], 'prob:', prob_np[0])

# Test with a realistic PE file vector (non-zero values)
pe_features = {f: 0.0 for f in features}
pe_features['filesize'] = 524288.0  # 512KB typical PE
pe_features['E_file'] = 6.2  # moderate entropy
pe_features['NumberOfSections'] = 5.0
pe_features['AddressOfEntryPoint'] = 4096.0
pe_features['ImageBase'] = 4194304.0
pe_features['SizeOfCode'] = 262144.0
pe_features['SizeOfInitializedData'] = 196608.0
pe_features['SizeOfImage'] = 786432.0
pe_features['SizeOfHeaders'] = 1024.0
pe_features['SectionAlignment'] = 4096.0
pe_features['FileAlignment'] = 512.0
pe_features['CreationYear'] = 2022.0
pe_features['non_sus_sections'] = 5.0
pe_features['MajorLinkerVersion'] = 14.0
pe_features['MajorSubsystemVersion'] = 6.0
pe_features['Subsystem'] = 2.0
pe_features['fileinfo'] = 1.0

realistic_df = pd.DataFrame([pe_features], columns=features)
scaled_real = scaler.transform(realistic_df)
pred_real = model.predict(scaled_real)
prob_real = model.predict_proba(scaled_real)
print('REALISTIC PE (benign-like) prediction:', pred_real[0], 'prob:', prob_real[0])

# Test malicious-like PE
mal_features = dict(pe_features)
mal_features['E_file'] = 7.8  # very high entropy (packed)
mal_features['sus_sections'] = 3.0
mal_features['packer'] = 1.0
mal_features['E_text'] = 7.5

mal_df = pd.DataFrame([mal_features], columns=features)
scaled_mal = scaler.transform(mal_df)
pred_mal = model.predict(scaled_mal)
prob_mal = model.predict_proba(scaled_mal)
print('MALICIOUS-LIKE PE prediction:', pred_mal[0], 'prob:', prob_mal[0])

print('\nModel type:', type(model).__name__)
print('Model n_features_in_:', model.n_features_in_)
