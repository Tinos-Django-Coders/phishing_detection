import os
import json
import socket
from urllib.parse import urlparse
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count, Q
from django.shortcuts import redirect, render
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.csrf import csrf_exempt
from .models import FeedbackReport, ScanLog

try:
    import joblib
except ImportError:
    joblib = None

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_model.pkl')
model = None

# Proactively load the model if it exists
if joblib and os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"Warning: Could not load machine learning model from {MODEL_PATH}: {e}")

@ensure_csrf_cookie
def dashboard(request):
    """
    Renders the main single page dashboard.
    """
    # Provide initial scan logs for the current user (or recent global logs for anonymous users)
    if request.user.is_authenticated:
        recent = ScanLog.objects.filter(user=request.user).order_by('-created_at')[:50]
    else:
        recent = ScanLog.objects.all().order_by('-created_at')[:50]

    initial_logs = []
    for log in recent:
        initial_logs.append({
            'id': str(log.id),
            'url': log.url,
            'timestamp': log.created_at.strftime('%Y.%m.%d %H:%M:%S'),
            'verdict': log.verdict,
            'score': round(log.confidence, 1),
            'ip': log.ip_address,
            'location': log.location,
            'domain_age': log.domain_age,
            'features': log.features or {}
        })

    context = {
        'initial_logs_json': json.dumps(initial_logs),
        'user_is_authenticated': request.user.is_authenticated,
    }
    return render(request, 'detector/index.html', context)

def admin_dashboard_login(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('admin_dashboard')

    if request.method == 'POST':
        email_or_username = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        username = email_or_username

        User = get_user_model()
        user_by_email = User.objects.filter(email__iexact=email_or_username).first()
        if user_by_email:
            username = user_by_email.get_username()

        user = authenticate(request, username=username, password=password)
        if user and user.is_staff:
            login(request, user)
            return redirect('admin_dashboard')

        messages.error(request, 'Invalid admin email or password.')

    return render(request, 'detector/admin_login.html')

@user_passes_test(lambda user: user.is_staff, login_url='admin_dashboard_login')
def admin_dashboard(request):
    query = request.GET.get('q', '').strip()
    verdict = request.GET.get('verdict', 'all')
    logs = ScanLog.objects.select_related('user').all()

    if query:
        logs = logs.filter(Q(url__icontains=query) | Q(ip_address__icontains=query) | Q(location__icontains=query))
    if verdict in {'PHISHING', 'LEGITIMATE'}:
        logs = logs.filter(verdict=verdict)

    total = ScanLog.objects.count()
    phishing = ScanLog.objects.filter(verdict='PHISHING').count()
    legitimate = ScanLog.objects.filter(verdict='LEGITIMATE').count()
    recent_logs = logs[:50]
    high_risk = ScanLog.objects.filter(verdict='PHISHING', confidence__gte=80).count()
    latest = ScanLog.objects.first()
    feedback_total = FeedbackReport.objects.count()
    feedback_correct = FeedbackReport.objects.filter(report_type='correct').count()
    feedback_false_positive = FeedbackReport.objects.filter(report_type='false_positive').count()
    feedback_missed_threat = FeedbackReport.objects.filter(report_type='missed_threat').count()
    feedback_max = max(feedback_correct, feedback_false_positive, feedback_missed_threat, 1)
    recent_feedback = FeedbackReport.objects.all()[:8]

    daily_counts = (
        ScanLog.objects.extra(select={'day': "date(created_at)"})
        .values('day')
        .annotate(total=Count('id'))
        .order_by('-day')[:7]
    )
    chart_rows = list(reversed(list(daily_counts)))
    max_count = max([row['total'] for row in chart_rows], default=1)

    # Build a simple users summary for the admin panel
    User = get_user_model()
    users_summary = (
        User.objects.annotate(scan_count=Count('scan_logs')).order_by('-scan_count')[:50]
    )

    context = {
        'logs': recent_logs,
        'query': query,
        'verdict': verdict,
        'total': total,
        'phishing': phishing,
        'legitimate': legitimate,
        'high_risk': high_risk,
        'latest': latest,
        'phishing_rate': round((phishing / total) * 100, 1) if total else 0,
        'chart_rows': chart_rows,
        'max_count': max_count,
        'feedback_total': feedback_total,
        'feedback_correct': feedback_correct,
        'feedback_false_positive': feedback_false_positive,
        'feedback_missed_threat': feedback_missed_threat,
        'feedback_max': feedback_max,
        'recent_feedback': recent_feedback,
        'users_summary': users_summary,
    }
    return render(request, 'detector/admin_dashboard.html', context)

def admin_dashboard_logout(request):
    logout(request)
    return redirect('admin_dashboard_login')


def user_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email_or_username = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        username = email_or_username

        User = get_user_model()
        user_by_email = User.objects.filter(email__iexact=email_or_username).first()
        if user_by_email:
            username = user_by_email.get_username()

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')

        messages.error(request, 'Invalid email or password.')

    return render(request, 'detector/login.html')


def user_logout(request):
    logout(request)
    return redirect('dashboard')


def user_signup(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')

        if not username or not email or not password:
            messages.error(request, 'Please fill all required fields.')
            return render(request, 'detector/signup.html')

        if password != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'detector/signup.html')

        User = get_user_model()
        if User.objects.filter(username__iexact=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'detector/signup.html')
        if User.objects.filter(email__iexact=email).exists():
            messages.error(request, 'An account with this email already exists.')
            return render(request, 'detector/signup.html')

        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
            login(request, user)
            messages.success(request, 'Account created and signed in.')
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, f'Account creation failed: {e}')

    return render(request, 'detector/signup.html')

def legal_page(request, page):
    if page == 'privacy-policy':
        title = 'Privacy Policy'
        intro = 'SENTINEL-X only processes URLs and scan metadata needed to classify phishing risk and operate the dashboard.'
        sections = [
            ('Data We Process', 'Submitted URLs, verdicts, confidence scores, IP lookups, timestamps, feedback notes, and basic admin account session data.'),
            ('How It Is Used', 'Data is used for threat analysis, dashboard reporting, classifier improvement, and operational troubleshooting.'),
            ('Retention', 'Scan logs remain in the local Django database until an administrator deletes them or the database is reset.'),
            ('Security', 'Admin dashboard access is restricted to staff users authenticated through Django.')
        ]
    else:
        title = 'Disclosures'
        intro = 'SENTINEL-X is a security analysis tool and should be used as a decision-support system, not a single source of truth.'
        sections = [
            ('Classification Limits', 'Machine learning and heuristic results can produce false positives or miss new threats. Treat high-risk results carefully.'),
            ('External Lookups', 'Domain, IP, and location information can be incomplete or approximate depending on network availability and public records.'),
            ('Responsible Use', 'Only scan URLs you are permitted to analyze. Do not use the tool to attack, harvest, or disrupt systems.'),
            ('No Warranty', 'The portal is provided for educational and defensive analysis workflows.')
        ]

    return render(request, 'detector/legal_page.html', {'title': title, 'intro': intro, 'sections': sections})

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
        from .feature_extractor import extract_features, extract_full_info, is_whitelisted
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

    # 2. Get prediction (whitelist → community votes → ML → heuristics)
    CORRECTION_THRESHOLD = 3

    if is_whitelisted(url):
        is_phishing = False
        confidence = 100.0
    else:
        false_positive_votes = FeedbackReport.objects.filter(
            url=url, report_type='false_positive'
        ).count()
        missed_threat_votes = FeedbackReport.objects.filter(
            url=url, report_type='missed_threat'
        ).count()

        if false_positive_votes >= CORRECTION_THRESHOLD and false_positive_votes > missed_threat_votes:
            is_phishing = False
            confidence = 100.0
        elif missed_threat_votes >= CORRECTION_THRESHOLD and missed_threat_votes > false_positive_votes:
            is_phishing = True
            confidence = 100.0
        elif model is not None:
            try:
                prediction = model.predict([feature_list])[0]
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
        ip = "Unknown"

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

    ScanLog.objects.create(
        url=url,
        verdict=verdict,
        confidence=confidence,
        ip_address=ip,
        location=response_data["location"],
        domain_age=response_data["domain_age"],
        features=feature_dict,
        user=request.user if request.user.is_authenticated else None,
    )

    return JsonResponse(response_data)

@csrf_exempt
def report_feedback(request):
    """
    Receives JSON feedback payload from the frontend to improve the classifier.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            report_type = data.get('reportType', '')
            valid_report_types = {'false_positive', 'missed_threat', 'correct'}
            if report_type not in valid_report_types:
                return JsonResponse({'status': 'error', 'message': 'Invalid report type'}, status=400)

            FeedbackReport.objects.create(
                url=data.get('url', ''),
                report_type=report_type,
                notes=data.get('notes', ''),
                reported_timestamp=data.get('timestamp', ''),
                features=data.get('features') or {},
            )
            return JsonResponse({'status': 'success', 'message': 'Feedback received'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'error': 'POST method required'}, status=400)
