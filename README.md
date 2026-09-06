# CyberSafe 🛡️

A browser extension that detects phishing and scam websites in real time using a machine learning model, with an AI security assistant built in.

## 🌟 Features

- **Real-time scanning** — Analyzes the current webpage as you browse
- **ML-based phishing detection** — A trained scikit-learn model flags suspicious sites
- **AI security assistant** — Integrates with Google's Generative Language API to explain risks and answer security questions
- **Lightweight popup UI** — Quick status and controls right from the browser toolbar

## 🛠️ Tech Stack

**Extension (Chrome, Manifest V3)**
- `manifest.json`, `background.js`, `content.js`, `analyzer.js`, `popup.html` / `popup.js`

**Backend**
- FastAPI (Python) — serves the ML model as an API
- scikit-learn — phishing/scam classification model
- pandas, joblib — data handling and model persistence

## 📂 Structure

```
CyberSafe_Extension_ML/
├── extension/     # Chrome extension (frontend, content scripts, popup)
└── backend/       # FastAPI service + ML model
```

## 🚀 Getting Started

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn src.main:app --reload
```

**Extension:**
1. Go to `chrome://extensions`
2. Enable Developer Mode
3. Click "Load unpacked" and select the `extension/` folder

## 📌 Notes

The extension communicates with a hosted backend (Render) for live predictions and with Google's Generative Language API for the assistant feature.
