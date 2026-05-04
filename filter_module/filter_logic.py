import re
from datetime import datetime

#черный список доменов
BLACKLIST_DOMAINS = [
    "malicious.com",
    "spamlink.ru",
    "badad.net",
    "phish.xyz",
    "danger.org",
]

#шаблоны подозрительных конструкций
SUSPICIOUS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"eval\s*\(",
    r"document\.cookie",
    r"\.exe",
    r"cmd\.exe",
    r"powershell",
    r"wscript\.shell",
    r"onerror\s*=",
    r"onload\s*=",
]

#сервисы коротких ссылок
SHORT_LINK_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "clck.ru",
    "ow.ly",
]

#хранилище логов в памяти
logs = []

def check_url(url):
    if not url:
        return True, None

def check_url(url): #проверка URL по черному списку и списку коротких ссылок
    if not url:
        return True, None #если URL пустой, считаем его безопасным
    for domain in BLACKLIST_DOMAINS:
        if domain in url.lower(): #проверка на наличие домена в черном списке
            return False, f"Домен {domain} в черном списке"
    for short in SHORT_LINK_SERVICES:
        if short in url.lower(): #проверка на наличие коротких ссылок
            return False, f"Короткие ссылки ({short}) блокируются"
    return True, None  #если ничего не найдено, URL считается безопасным


def check_content(text): #проверка контента на наличие запрещенных паттернов
    if not text:
        return True, None #если контент пустой, считаем его безопасным
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE): #поиск паттернов в тексте
            return False, f"Обнаружен запрещенный паттерн: {pattern}"
    return True, None  #если ничего не найдено, контент считается безопасным


def add_log(url, content, decision, reason, user_ip="127.0.0.1"): #добавление записи в журнал событий
    log_entry = { #создание записи журнала
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_ip": user_ip,
        "url": url[:80],
        "content_preview": content[:40] + "..." if len(content) > 40 else content, 
        "decision": decision,
        "reason": reason,
    }
    logs.append(log_entry) #добавление записи в список логов
    return log_entry


def get_logs(count=20): #возвращает последние записи журнала
    return logs[-count:] 


def get_stats(): #возвращает статистику разрешенных/заблокированных проверок
    allowed = sum(1 for log in logs if log["decision"] == "ALLOWED")
    blocked = sum(1 for log in logs if log["decision"] == "BLOCKED")
    return {"allowed": allowed, "blocked": blocked}  #возвращает словарь со статистикой
