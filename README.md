# 🛡️ Phishing Detection System

A **Rule-Based Cybersecurity Project** that detects phishing URLs and plagiarized text using Flask, Python, and frontend technologies — without relying on any external APIs or AI models.

---

## 🚀 Project Overview

This project analyzes **URLs** and **text documents** (PDF/TXT) to detect:
- Phishing links or impersonated domains
- Plagiarized or repeated text content

It uses **rule-based logic** instead of AI, ensuring offline use and transparent decision-making.

---

## 🧠 Features

- **URL Analysis** – Detects suspicious TLDs, subdomains, phishing keywords, and brand impersonation.  
- **Text Analysis** – Extracts and checks PDF/TXT files for duplicated or plagiarized content.  
- **Dual Functionality** – Handles both phishing and plagiarism in a single web interface.  
- **Rule-Based Detection** – Provides clear, explainable results.  
- **Risk Scoring** – Generates a numerical score with Safe / Suspicious / Phishing status.  

---

## ⚙️ Technologies Used

**Frontend:** HTML, CSS, JavaScript  
**Backend:** Python (Flask Framework)  
**Libraries:**  
- `PyPDF2` – Extracts text from PDF files  
- `re` – Regex for phishing keyword detection  
- `difflib` – Detects repeated or copied text  
- `urllib.parse` – URL structure analysis  
- `socket` – Identifies IP-based URLs  

---

## 🏗️ System Architecture

1. User uploads a file or enters a URL.  
2. Flask backend routes to `/analyze` (file) or `/analyze-url` (link).  
3. For files → Text is extracted and analyzed for plagiarism.  
4. For URLs → The system checks domain, TLD, and keywords.  
5. A **risk score (0–100)** is calculated.  
6. Results are displayed with visual highlights and recommendations.

---

## 📊 Output Example

- **Safe:** The URL or text shows no signs of threat or plagiarism.  
- **Suspicious:** Some irregular patterns or keywords detected.  
- **Phishing:** Multiple high-risk indicators found.  
- **Plagiarism:** Similar or repeated sentences highlighted in yellow.

---

## 🧩 How to Run the Project Locally

### 1. Clone the repository
```bash
git clone https://github.com/your_username/Phishing_Plagiarism_Detection.git
cd Phishing_Plagiarism_Detection
