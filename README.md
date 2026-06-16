# SentinelAI v1.0

AI-Powered Phishing Detection & Threat Intelligence Platform

---

# Overview

SentinelAI is a phishing detection and threat intelligence platform designed to analyze suspicious emails and identify phishing indicators using machine learning and rule-based threat analysis.

The system combines:

- DistilBERT phishing classification
- URL analysis
- IOC extraction
- MITRE ATT&CK mapping
- OCR processing
- Threat scoring
- Security reporting
- Streamlit dashboard

Current Version:

Version: v1.0

Status: Stable

---

# Features

## Email Analysis

- DistilBERT email classifier
- Phishing detection
- Confidence scoring

## URL Analysis

- URL extraction
- Domain inspection
- Suspicious URL detection

## Threat Intelligence

- IOC extraction
- MITRE ATT&CK mapping
- Threat scoring

## OCR

- Extract text from images
- Analyze screenshots and image-based phishing attempts

## Reporting

- Executive summary
- Threat score
- Severity assessment
- Recommendations

## Dashboard

- Streamlit interface
- Historical scans
- Threat visualization

---

# Project Structure

SentinelAI/

```text
data/
├── raw/
│   ├── enron/
│   ├── nazario/
│   └── phishing_email.csv/

models/
├── final_sentinel_distilbert/
│   ├── config.json
│   ├── model.safetensors
│   ├── tokenizer.json
│   └── tokenizer_config.json

notebooks/
├── model_training.ipynb
├── train_distilbert.ipynb

src/
├── distilbert_predict.py
├── pipeline.py
├── predict.py
├── preprocess.py
├── url_analyzer.py
├── ioc_extractor.py
├── mitre_mapper.py
├── explainability.py
├── recommendations.py
├── report_generator.py
├── history.py
├── ocr.py

tests/
├── test_distilbert.py
├── test_distilbert1.py
├── test_distilbert2.py
├── test_distilbert3.py
```

---

# DistilBERT Model

Production model location:

```text
models/final_sentinel_distilbert
```

Training Dataset:

- Enron emails
- Nazario phishing corpus
- Kaggle phishing dataset

Combined Dataset Size:

~82,000 emails

Validation Accuracy:

~99.3%

Validation F1:

~99.3%

---

# Installation

Clone repository

```bash
git clone https://github.com/pavankumark24/SentinelAI.git
cd SentinelAI
```

Create virtual environment

```bash
python -m venv venv
```

Activate environment

Windows:

```bash
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Running Streamlit

From project root:

```bash
streamlit run app.py
```

Open:

```text
http://localhost:8501
```

---

# Testing DistilBERT

Run:

```bash
python -m tests.test_distilbert
```

Expected Output:

```text
1
0.98
```

Example Legit Test:

```bash
python -m tests.test_distilbert1
```

---

# Training DistilBERT Again

Open:

```text
notebooks/train_distilbert.ipynb
```

Training Environment:

- Google Colab
- Tesla T4 GPU

Dataset:

```text
phishing_email.csv
```

Model:

```python
DistilBertForSequenceClassification
```

Training Time:

Approximately 30 minutes on T4 GPU

After training:

```python
model.save_pretrained("/content/final_sentinel_distilbert")
tokenizer.save_pretrained("/content/final_sentinel_distilbert")
```

Download folder and replace:

```text
models/final_sentinel_distilbert
```

---

# Current Limitations

Not Yet Implemented:

- Email forwarding workflow
- Mailbox integration
- Automated email responses
- Payload detonation
- Malware sandbox
- PDF malware analysis
- Office macro analysis
- ZIP inspection
- YARA scanning

These are planned for Phase 2.

---

# Future Roadmap

## Phase 2

### Automated Email Submission

User forwards suspicious email

↓

SentinelAI receives email

↓

Automatic analysis

↓

Generate report

↓

Reply to sender

### Payload Analysis

- PDF inspection
- DOCX macro detection
- ZIP analysis
- Executable analysis
- Sandbox execution

### Enterprise Features

- User authentication
- Analyst dashboard
- SOC workflow integration
- Ticket generation

---

# Common Problems

## DistilBERT Model Not Found

Check:

```text
models/final_sentinel_distilbert
```

contains:

```text
config.json
model.safetensors
tokenizer.json
tokenizer_config.json
```

---

## Streamlit Not Starting

Install:

```bash
pip install streamlit
```

Run:

```bash
streamlit run app.py
```

---

## Torch Missing

Install:

```bash
pip install torch transformers
```

---

# Release Notes

Version: v1.0

Major Achievements:

- DistilBERT Integration
- 82K Email Dataset
- OCR Support
- IOC Extraction
- MITRE ATT&CK Mapping
- Threat Scoring
- Streamlit Dashboard

Status:

Production Demo Ready

Date:

June 2026

---

# Author

Pavan Kumar

SentinelAI v1.0
AI-Powered Phishing Detection & Threat Intelligence Platform