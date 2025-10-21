from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import re
from difflib import SequenceMatcher
from PyPDF2 import PdfReader
from urllib.parse import urlparse
import socket

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Known legitimate domains
TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 'apple.com',
    'netflix.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'paypal.com'
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']

# Phishing keywords in URLs
PHISHING_KEYWORDS = [
    'verify', 'account', 'update', 'secure', 'banking', 'login', 'signin',
    'suspended', 'locked', 'confirm', 'password', 'paypal', 'amazon', 'microsoft'
]

def extract_text(file_path):
    text = ""
    try:
        if file_path.endswith('.pdf'):
            reader = PdfReader(file_path)
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        elif file_path.endswith('.txt'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
    except Exception as e:
        print("Error extracting text:", e)
    return text.strip()

def analyze_url(url):
    """Analyze a single URL for phishing indicators"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
        
        risk_factors = []
        risk_score = 0
        
        # Check for IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            risk_factors.append("Uses IP address instead of domain name")
            risk_score += 30
        
        # Check URL length (phishing URLs are often long)
        if len(url) > 75:
            risk_factors.append("Unusually long URL")
            risk_score += 15
        
        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                risk_factors.append(f"Suspicious top-level domain ({tld})")
                risk_score += 25
                break
        
        # Check for multiple subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 2:
            risk_factors.append(f"Multiple subdomains ({subdomain_count})")
            risk_score += 20
        
        # Check for phishing keywords in URL
        for keyword in PHISHING_KEYWORDS:
            if keyword in full_url:
                risk_factors.append(f"Contains phishing keyword: '{keyword}'")
                risk_score += 10
        
        # Check for @ symbol (URL obfuscation)
        if '@' in url:
            risk_factors.append("Contains @ symbol (URL obfuscation)")
            risk_score += 35
        
        # Check for suspicious characters
        if '//' in path or '\\' in url:
            risk_factors.append("Contains suspicious path separators")
            risk_score += 15
        
        # Check for brand impersonation
        base_domain = domain.split('.')[-2] if domain.count('.') > 0 else domain
        for trusted in TRUSTED_DOMAINS:
            trusted_base = trusted.split('.')[0]
            if trusted_base in domain and domain != trusted:
                risk_factors.append(f"Possible brand impersonation: {trusted}")
                risk_score += 40
                break
        
        # Check if domain is in trusted list
        is_trusted = any(domain.endswith(trusted) for trusted in TRUSTED_DOMAINS)
        if is_trusted:
            risk_factors.append("âœ… Domain appears in trusted list")
            risk_score = max(0, risk_score - 30)
        
        # Determine status
        risk_score = min(100, risk_score)
        if risk_score >= 60:
            status = "PHISHING"
        elif risk_score >= 30:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"
        
        return {
            "url": url,
            "domain": domain,
            "status": status,
            "riskScore": risk_score,
            "riskFactors": risk_factors if risk_factors else ["No major risk factors detected"]
        }
        
    except Exception as e:
        return {
            "url": url,
            "status": "ERROR",
            "riskScore": 0,
            "riskFactors": [f"Error analyzing URL: {str(e)}"]
        }

def analyze_text(text):
    if not text:
        return {"error": "No text content extracted"}

    urls = re.findall(r'https?://\S+', text)
    urgency_words = re.findall(r'\b(urgent|immediately|verify|account|click|password|login|bank|suspended|locked|confirm)\b', text, flags=re.IGNORECASE)

    lines = [line.strip() for line in text.split('\n') if len(line.strip()) > 30]
    flagged_sections = []

    for i, l1 in enumerate(lines):
        for j, l2 in enumerate(lines):
            if i != j:
                similarity = SequenceMatcher(None, l1, l2).ratio()
                if similarity > 0.85:
                    flagged_sections.append({
                        "text": l1,
                        "reason": "Repeated or copied content detected",
                        "similarity": round(similarity * 100, 2)
                    })
                    break

    risk_score = min(100, len(urls)*10 + len(urgency_words)*8 + len(flagged_sections)*5)

    return {
        "text": text,
        "urls": urls,
        "urgencyWords": urgency_words,
        "flaggedSections": flagged_sections,
        "riskScore": risk_score
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        text = extract_text(file_path)
        results = analyze_text(text)
        results['fileName'] = filename

        return jsonify(results)
    except Exception as e:
        print("Server Error:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/analyze-url', methods=['POST'])
def analyze_url_endpoint():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Add http:// if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        result = analyze_url(url)
        return jsonify(result)
        
    except Exception as e:
        print("Server Error:", e)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)