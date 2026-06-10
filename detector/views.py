import joblib
import os
from django.shortcuts import render
from .forms import URLInputForm
from .feature_extractor import extract_features, extract_full_info

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'phishing_model.pkl')
model = joblib.load(MODEL_PATH)

def check_url(request):
    result = None
    confidence = None
    info = None
    url = None

    if request.method == 'POST':
        form = URLInputForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            features = extract_features(url)
            prediction = model.predict([features])[0]
            confidence = round(model.predict_proba([features])[0].max() * 100, 1)
            result = 'Phishing' if prediction == 1 else 'Legitimate'
            info = extract_full_info(url)
    else:
        form = URLInputForm()

    return render(request, 'detector/index.html', {
        'form': form,
        'result': result,
        'confidence': confidence,
        'info': info,
        'url': url
    })