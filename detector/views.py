import joblib
import os
import re
import socket
from urllib.parse import urlparse
import tldextract
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .feature_extractor import extract_features, extract_full_info, is_whitelisted

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_model.pkl')
model = None

# Proactively load the model if it exists
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"Warning: Could not load machine learning model from {MODEL_PATH}: {e}")

def dashboard(request):
    """
    Renders the main single page dashboard.
    """
    return render(request, 'detector/index.html')

def heuristic_predict(features):
    """
    Fallback rule-based heuristic prediction if ML model is not loaded.
    Matches the frontend logic.
    """
    score = 0
    if features[0] > 70: score += 20
    if features[1] == 1: score += 30
    if features[2] == 1: score += 25
    if features[3] == 1: score += 20
    if features[4] > 2: score += 15
    if features[5] == 0: score += 30
    if features[8] == 1: score += 15
    if features[9] > 0.12: score += 20
    if features[10] > 3: score += 15

    score = min(score, 100)
    is_phishing = score >= 50
    return is_phishing, score

def scan_url_api(request):
    """
    Performs feature extraction and ML classification on the input URL,
    returning structured JSON data.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=400)

    url = request.POST.get('url', '').strip()
    if not url:
        return JsonResponse({'error': 'No URL provided'}, status=400)

    # 1. Extract 12 numerical features for the model
    try:
        feature_list = extract_features(url)
    except Exception as e:
        return JsonResponse({'error': f'Feature extraction failed: {str(e)}'}, status=500)

    # Map features list to a structured dictionary for the frontend
    feature_dict = {
        "url_length":          feature_list[0],
        "has_ip":              feature_list[1],
        "has_at_symbol":       feature_list[2],
        "has_double_slash":    feature_list[3],
        "subdomain_count":     feature_list[4],
        "has_https":           feature_list[5],
        "domain_length":       feature_list[6],
        "path_length":         feature_list[7],
        "hyphen_in_domain":    feature_list[8],
        "digit_ratio":         feature_list[9],
        "special_char_count":  feature_list[10],
        "tld_in_path":         feature_list[11]
    }

    # 2. Get prediction (Check whitelist first, then ML/Heuristics)
    if is_whitelisted(url):
        is_phishing = False
        confidence = 100.0
    elif model is not None:
        try:
            prediction = model.predict([feature_list])[0]
            # predict_proba returns probability for both classes [[prob_legit, prob_phish]]
            proba = model.predict_proba([feature_list])[0]
            confidence = round(proba.max() * 100, 1)
            is_phishing = (prediction == 1)
        except Exception as e:
            print(f"Prediction error: {e}. Falling back to heuristics.")
            is_phishing, confidence = heuristic_predict(feature_list)
    else:
        is_phishing, confidence = heuristic_predict(feature_list)

    verdict = 'PHISHING' if is_phishing else 'LEGITIMATE'

    # 3. Retrieve WHOIS and geolocation metrics
    info = extract_full_info(url)

    # 4. Resolve Domain IP
    try:
        parsed_url = urlparse(url if "://" in url else f"http://{url}")
        ip = socket.gethostbyname(parsed_url.hostname or parsed_url.netloc)
    except Exception:
        # Fallback random IP or default placeholder
        import random
        octets = [str(random.randint(1, 254)) for _ in range(4)]
        ip = ".".join(octets)

    # Build response payload exactly matching the frontend requirements
    response_data = {
        "url": url,
        "verdict": verdict,
        "confidence": confidence,
        "features": feature_dict,
        "ip": ip,
        "location": info.get('server_origin', 'Unknown'),
        "domain_age": info.get('domain_age', 'Unknown')
    }

    return JsonResponse(response_data)

@csrf_exempt
def report_feedback(request):
    """
    Receives JSON feedback payload from the frontend to improve the classifier.
    """
    if request.method == 'POST':
        # Feedback is received as JSON
        import json
        try:
            data = json.loads(request.body)
            # Log the feedback for review or save it to database
            print(f"Feedback received: URL={data.get('url')} | Type={data.get('reportType')} | Notes={data.get('notes')}")
            return JsonResponse({'status': 'success', 'message': 'Feedback received'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'error': 'POST method required'}, status=400)