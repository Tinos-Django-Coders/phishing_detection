from django import forms

class URLInputForm(forms.Form):
    url = forms.URLField(
        label='Enter URL',
        widget=forms.URLInput(attrs={
            'placeholder': 'https://example.com',
            'class': 'form-control'
        })
    )