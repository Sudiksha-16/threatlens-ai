
# ThreatLens AI 🛡️
### AI-Powered Malware Classification & Threat Detection System

ThreatLens AI is an intelligent, web-based malware detection platform designed to identify potentially malicious files through static analysis, machine learning, signature-based detection, and threat intelligence. It combines traditional cybersecurity techniques with machine learning to provide file classification, risk assessment, and detailed security reports through an interactive dashboard.

---

## 🚀 Key Features

### 🔐 Authentication & User Management
- Secure user registration and login.
- JWT-based authentication.
- Protected application routes and user-specific scan history.

### 📁 File Upload & Analysis
- Upload and analyze suspicious files through a web interface.
- File validation and size restriction.
- Windows Portable Executable (PE) file identification.
- Cryptographic hashing using SHA-256 and MD5.
- File entropy and structural analysis.

### 🤖 AI-Powered Malware Detection
- Machine learning-based binary classification.
- Random Forest-based malware prediction.
- Analysis of 69 structural PE file attributes.
- Malicious probability and prediction confidence.
- Model-based identification of potentially harmful executables.

### 🔍 YARA Signature Detection
- Signature-based malware detection using YARA.
- Identification of known suspicious patterns.
- Detection of potentially malicious file characteristics.

### 🌐 Threat Intelligence Integration
- VirusTotal hash-based lookup.
- Retrieval of threat intelligence information.
- Additional verification when machine learning classification is unavailable.

### 📊 Risk Assessment & Analytics
- Automated threat scoring.
- Risk categorization into severity levels.
- Identification of suspicious file characteristics.
- Security alerts for high-risk findings.
- Malware analytics dashboard and scan history.

### 📄 Reports & Monitoring
- Detailed scan reports.
- Technical file analysis.
- Executive security summaries.
- Downloadable PDF reports.
- Centralized monitoring dashboard.

---

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Frontend | React.js, JavaScript, Tailwind CSS |
| Backend | Python, FastAPI |
| Database | MongoDB |
| Authentication | JWT |
| Machine Learning | Scikit-learn, NumPy, Pandas |
| ML Algorithms | Random Forest, Logistic Regression, Decision Tree, SVM |
| Malware Analysis | PE File Analysis, Static Analysis, Entropy Analysis |
| Signature Detection | YARA |
| Threat Intelligence | VirusTotal API |
| Development Tools | Git, GitHub, VS Code |

---

## 🧠 Machine Learning Approach

ThreatLens AI uses a supervised machine learning pipeline to classify executable files into benign and malicious categories.

### Dataset
The project uses malware datasets including:

- ClaMP Integrated PE Dataset
- DA-Proj Malware Families Dataset

### Model Development

Multiple machine learning algorithms are trained and evaluated:

1. Logistic Regression
2. Decision Tree
3. Random Forest
4. Support Vector Machine (SVM)

A model comparison process is used to evaluate their classification performance and select the binary classification model.

### Feature Engineering

The binary classification pipeline uses **69 structural features** extracted from Windows PE files, covering:

- DOS header information
- PE file header characteristics
- Optional header attributes
- DLL characteristics
- Section information
- File entropy
- File size and metadata
- Packer-related attributes

The extracted features are transformed using a trained StandardScaler before being passed to the classification model.

---

## ⚙️ System Architecture

ThreatLens AI follows a modular client-server architecture.

```text
                 USER
                   |
                   v
          REACT FRONTEND
                   |
              REST APIs
                   |
                   v
           FASTAPI BACKEND
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
   STATIC       YARA        MACHINE
   ANALYSIS     ENGINE      LEARNING
       |           |           |
       +-----------+-----------+
                   |
                   v
          THREAT INTELLIGENCE
              VIRUSTOTAL
                   |
                   v
            RISK ASSESSMENT
                   |
          +--------+--------+
          |                 |
          v                 v
       MONGODB          SCAN REPORTS
          |                 |
          +--------+--------+
                   |
                   v
            DASHBOARD &
            ANALYTICS
```

---

## 📂 Project Structure

```text
Threatlens/
│
├── backend/
│   ├── app/
│   │   ├── routers/
│   │   ├── services/
│   │   ├── models/
│   │   ├── core/
│   │   └── config/
│   ├── uploads/
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── assets/
│   └── package.json
│
├── training/
│   ├── preprocess.py
│   └── train_models.py
│
├── yara_rules/
│   └── malware_rules.yar
│
├── reports/
│
├── .env.example
├── .gitignore
├── README.md
└── docker-compose.yml
```

---

## 💻 Installation & Setup

### Prerequisites

- Python 3.10+
- Node.js and npm
- MongoDB
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/Threatlens.git
cd Threatlens
```

### 2. Backend Setup

Create and activate a Python virtual environment:

```bash
python -m venv venv
```

Windows:

```powershell
.\venv\Scripts\activate
```

Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root using `.env.example` as a reference.

Configure the following:

```env
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=threatlens_ai
JWT_SECRET=your_secure_secret_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Use your own secure JWT secret and VirusTotal API key.

### 4. Start MongoDB

Ensure your MongoDB service is running locally.

### 5. Start the Backend

From the project root:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Backend API:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

### 6. Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
```

Start the frontend:

```bash
npm run dev
```

Open the application in your browser using the local URL displayed by Vite.

---

## 🔑 External Services

### VirusTotal API

ThreatLens AI integrates VirusTotal for hash-based threat intelligence lookups.

To enable this integration:

1. Create a VirusTotal account.
2. Obtain your API key.
3. Add the key to your backend environment configuration.

---

## 🔒 Security Considerations

- JWT-based authentication for protected resources.
- Environment-based configuration for sensitive credentials.
- File validation before analysis.
- Temporary file handling and cleanup.
- Static analysis without intentionally executing uploaded files.
- Hash-based threat intelligence lookups.

---

## 🔮 Future Enhancements

- Expanded malware family classification.
- Advanced behavioral analysis in an isolated environment.
- Enhanced threat intelligence integrations.
- Improved model evaluation and calibration.
- Real-time security monitoring.
- Extended malware detection capabilities.

---

## ⚠️ Disclaimer

ThreatLens AI is developed for educational, research, and cybersecurity analysis purposes. Machine learning predictions and threat intelligence results should be interpreted as indicators rather than absolute guarantees of file safety. Suspicious files should always be handled in an isolated and secure environment.

---

## 👩‍💻 Author

**D. Sudiksha**

Computer Science and Engineering – Artificial Intelligence & Machine Learning


---

<p align="center">
  <b>ThreatLens AI — Intelligent Detection. Stronger Cybersecurity.</b>
</p>
