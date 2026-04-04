from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd

from features import extract_features

from urllib.parse import urlparse

TRUSTED_DOMAINS = [
    # 🌍 Global
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "linkedin.com", "github.com", "microsoft.com",
    "apple.com", "openai.com",

    # 🛒 E-commerce
    "amazon.in", "amazon.com", "flipkart.com", "myntra.com",
    "meesho.com", "ajio.com", "snapdeal.com",

    # 💰 Banking (India)
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "bankofbaroda.in",
    "pnbindia.in",

    # 🏛️ Government
    "gov.in", "nic.in", "india.gov.in",
    "uidai.gov.in", "incometax.gov.in",
    "irctc.co.in", "epfindia.gov.in",

    # 📱 Telecom / Payments
    "paytm.com", "phonepe.com", "bharatpe.com",
    "airtel.in", "jio.com", "vi.in",

    # 📦 Delivery / Services
    "zomato.com", "swiggy.com", "ola.com", "uber.com"
]

def is_trusted(url):
    try:
        domain = urlparse(url).netloc.lower()

        for d in TRUSTED_DOMAINS:
            if domain == d or domain.endswith("." + d):
                return True

        return False
    except:
        return False

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model
model_data = joblib.load("../model/cybersafe_model.pkl")

# Handle saved format
if isinstance(model_data, dict):
    model = model_data["model"]
    label_encoder = model_data["label_encoder"]
else:
    model = model_data
    label_encoder = None


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {"message": "CyberSafe API running"}


@app.post("/predict")
def predict(request: URLRequest):
    try:
        url = request.url

         # 🔥 STEP 1 FIX: trusted domain override
        if is_trusted(url):
            return {
                "url": url,
                "prediction": "benign",
                "confidence": 1.0
            }

        features = extract_features(url)
        df = pd.DataFrame([features])

        pred = model.predict(df)[0]

        if label_encoder:
            label = label_encoder.inverse_transform([pred])[0]
        else:
            label = str(pred)

        prob = max(model.predict_proba(df)[0])

        return {
            "url": url,
            "prediction": label,
            "confidence": float(prob)
        }

    except Exception as e:
        return {"error": str(e)}