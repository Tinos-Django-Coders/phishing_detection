from django.contrib import admin
from .models import FeedbackReport, ScanLog

@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ('url', 'verdict', 'confidence', 'ip_address', 'created_at')
    list_filter = ('verdict', 'created_at')
    search_fields = ('url', 'ip_address', 'location')
    readonly_fields = ('created_at',)

@admin.register(FeedbackReport)
class FeedbackReportAdmin(admin.ModelAdmin):
    list_display = ('url', 'report_type', 'created_at')
    list_filter = ('report_type', 'created_at')
    search_fields = ('url', 'notes')
    readonly_fields = ('created_at',)
