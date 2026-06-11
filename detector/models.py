from django.conf import settings
from django.db import models

class ScanLog(models.Model):
    VERDICT_CHOICES = [
        ('PHISHING', 'Phishing'),
        ('LEGITIMATE', 'Legitimate'),
    ]

    url = models.TextField()
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    confidence = models.FloatField(default=0)
    ip_address = models.CharField(max_length=64, blank=True)
    location = models.CharField(max_length=255, blank=True)
    domain_age = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='scan_logs'
    )
    features = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.verdict}: {self.url[:80]}"

class FeedbackReport(models.Model):
    REPORT_CHOICES = [
        ('false_positive', 'False positive'),
        ('missed_threat', 'Missed threat'),
        ('correct', 'Correct'),
    ]

    url = models.TextField()
    report_type = models.CharField(max_length=32, choices=REPORT_CHOICES)
    notes = models.TextField(blank=True)
    reported_timestamp = models.CharField(max_length=64, blank=True)
    features = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_report_type_display()}: {self.url[:80]}"
