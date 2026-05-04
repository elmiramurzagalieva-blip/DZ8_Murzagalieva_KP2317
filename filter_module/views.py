# Представления Django для модуля фильтрации
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

from .filter_logic import check_url, check_content, add_log, get_logs, get_stats


def index(request):
    """Главная страница модуля фильтрации"""
    return render(request, "filter_module/index.html")


@csrf_exempt
def api_check(request):
    """API для проверки URL и контента"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        url = data.get("url", "")
        content = data.get("content", "")
        user_ip = request.META.get("REMOTE_ADDR", "127.0.0.1")

        url_allowed, url_reason = check_url(url)
        content_allowed, content_reason = check_content(content)

        if not url_allowed:
            decision, reason = "BLOCKED", url_reason
        elif not content_allowed:
            decision, reason = "BLOCKED", content_reason
        else:
            decision, reason = "ALLOWED", "Контент безопасен"

        log_entry = add_log(url, content, decision, reason, user_ip)

        return JsonResponse(
            {
                "decision": decision,
                "reason": reason,
                "log": log_entry,
            }
        )

    return JsonResponse({"error": "Метод не поддерживается"}, status=405)


def api_logs(request):
    """API для получения журнала проверок"""
    logs_data = get_logs(20)
    return JsonResponse(logs_data, safe=False)


def api_stats(request):
    """API для получения статистики"""
    stats = get_stats()
    return JsonResponse(stats)
