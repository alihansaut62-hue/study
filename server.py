import datetime
import os
import socket
import ssl
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)

@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL не указан'}), 400

    parsed = urlparse(url)
    hostname = parsed.hostname
    scheme = parsed.scheme or 'https'
    base_url = f"{scheme}://{hostname}"

    if not hostname:
        return jsonify({'error': 'Некорректный URL'}), 400

    try:
        resp = requests.get(base_url, timeout=10, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'})
    except Exception as e:
        return jsonify({'error': f'Не удалось подключиться к сайту: {str(e)}'}), 400

    headers = resp.headers

    security_headers = analyze_security_headers(headers)
    ssl_info = check_ssl(hostname)
    ports_info = scan_common_ports(hostname)
    techs = detect_technologies(headers, resp.text)
    leaks = find_info_leaks(base_url, headers, resp.text)
    backend_tips = build_backend_protection_tips(security_headers, ports_info, leaks, scheme)

    bad_headers = sum(1 for h in security_headers if '❌' in h.get('status', ''))
    # Считаем только реально опасные открытые порты (не 80 и 443)
    open_ports = sum(1 for p in ports_info if p.get('open') and p.get('dangerous'))
    leak_count = sum(1 for l in leaks if 'УТЕЧКА' in l.get('status', ''))
    critical_count = bad_headers + open_ports

    if critical_count >= 4 or leak_count >= 2:
        risk_level = 'КРИТИЧЕСКИЙ'
    elif critical_count >= 2 or leak_count >= 1:
        risk_level = 'ВЫСОКИЙ'
    elif bad_headers >= 1:
        risk_level = 'СРЕДНИЙ'
    else:
        risk_level = 'НИЗКИЙ'

    human_advice = build_human_advice(
        risk_level=risk_level,
        security_headers=security_headers,
        ports_info=ports_info,
        leaks=leaks,
        scheme=scheme
    )

    return jsonify({
        'url': base_url,
        'risk_level': risk_level,
        'critical_count': critical_count,
        'security_headers': security_headers,
        'ssl_security': ssl_info,
        'ports': ports_info,
        'technologies': techs,
        'info_disclosure': leaks,
        'backend_protection': backend_tips,
        'human_advice': human_advice
    })


def analyze_security_headers(headers):
    hdr_lower = {k.lower(): v for k, v in headers.items()}

    checks = [
        {
            'name': 'Content-Security-Policy',
            'check': 'content-security-policy' in hdr_lower,
            'risk': 'XSS, инъекции данных',
            'exploit': 'Внедрение вредоносных скриптов',
            'fix': 'Добавьте заголовок Content-Security-Policy'
        },
        {
            'name': 'X-Frame-Options',
            'check': 'x-frame-options' in hdr_lower,
            'risk': 'Clickjacking',
            'exploit': 'Перехват кликов через iframe',
            'fix': 'X-Frame-Options: DENY или SAMEORIGIN'
        },
        {
            'name': 'X-Content-Type-Options',
            'check': 'x-content-type-options' in hdr_lower,
            'risk': 'MIME sniffing',
            'exploit': 'Подмена типа контента',
            'fix': 'X-Content-Type-Options: nosniff'
        },
        {
            'name': 'Strict-Transport-Security',
            'check': 'strict-transport-security' in hdr_lower,
            'risk': 'Downgrade атаки',
            'exploit': 'Принуждение к HTTP',
            'fix': 'Strict-Transport-Security: max-age=31536000'
        },
        {
            'name': 'Referrer-Policy',
            'check': 'referrer-policy' in hdr_lower,
            'risk': 'Утечка URL',
            'exploit': 'Раскрытие конфиденциальных путей',
            'fix': 'Referrer-Policy: strict-origin-when-cross-origin'
        },
        {
            'name': 'Permissions-Policy',
            'check': 'permissions-policy' in hdr_lower,
            'risk': 'Доступ к API браузера',
            'exploit': 'Злоупотребление камерой/микрофоном',
            'fix': 'Permissions-Policy: camera=(), microphone=()'
        },
        {
            'name': 'Server',
            'check': 'server' not in hdr_lower,
            'risk': 'Раскрытие версии сервера',
            'exploit': 'Поиск эксплойтов под версию',
            'fix': 'Скройте или измените заголовок Server',
            'value': hdr_lower.get('server', 'Отсутствует')
        }
    ]

    results = []
    for c in checks:
        passed = c['check']
        status = '✅ ХОРОШО' if passed else '❌ КРИТИЧНО'
        results.append({
            'name': c['name'],
            'status': status,
            'risk': c['risk'],
            'exploit': c['exploit'],
            'fix': c['fix'],
            'critical': not passed,
            'value': c.get('value') if 'value' in c else (
                hdr_lower.get(c['name'].lower(), 'Не задан') if not passed else '')
        })

    return results


def check_ssl(hostname):
    results = []
    try:
        # ИСПРАВЛЕНО: таймаут устанавливается ДО wrap_socket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(5)

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw_sock, server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

            # ИСПРАВЛЕНО: сравнение с UTC
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.datetime.utcnow()).days

            if days_left > 30:
                status, risk = '✅ ХОРОШО', 'Сертификат действителен'
            elif days_left > 0:
                status, risk = '⚠ ВНИМАНИЕ', f'Истекает через {days_left} дней'
            else:
                status, risk = '❌ КРИТИЧНО', 'Сертификат истёк'

            results.append({
                'name': 'Срок действия',
                'status': status,
                'risk': risk,
                'exploit': 'MITM-атаки',
                'fix': 'Обновите сертификат'
            })

            issuer = dict(x[0] for x in cert['issuer'])
            results.append({
                'name': 'Издатель',
                'status': 'ℹ ИНФОРМАЦИЯ',
                'risk': issuer.get('organizationName', 'Неизвестно'),
                'exploit': '',
                'fix': ''
            })

            tls_version = s.version()
            results.append({
                'name': 'TLS версия',
                'status': '✅ ХОРОШО' if tls_version == 'TLSv1.3' else '⚠ ВНИМАНИЕ',
                'risk': f'Используется {tls_version}',
                'exploit': 'Устаревшие протоколы уязвимы',
                'fix': 'Включите TLS 1.3'
            })

    except Exception as e:
        results.append({
            'name': 'SSL/TLS',
            'status': '❌ ОШИБКА',
            'risk': str(e),
            'exploit': '',
            'fix': 'Проверьте конфигурацию SSL'
        })

    return results


def scan_common_ports(hostname):
    # ИСПРАВЛЕНО: разделены "опасные" и "нормальные" открытые порты
    common_ports = {
        21:    ('FTP',        True,  'Возможен анонимный вход'),
        22:    ('SSH',        True,  'Перебор паролей'),
        23:    ('Telnet',     True,  'Незашифрованный трафик'),
        25:    ('SMTP',       False, 'Почтовый сервер'),
        80:    ('HTTP',       False, 'Стандартный веб-порт'),
        443:   ('HTTPS',      False, 'Стандартный HTTPS-порт'),
        3306:  ('MySQL',      True,  'SQL-инъекции при слабом пароле'),
        5432:  ('PostgreSQL', True,  'Потенциальный вектор атаки'),
        27017: ('MongoDB',    True,  'NoSQL-инъекции, утечка данных'),
        6379:  ('Redis',      True,  'Выполнение команд при отсутствии пароля'),
    }

    results = []
    for port, (service, dangerous, danger_risk) in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            sock.close()

            is_open = result == 0

            if is_open:
                if dangerous:
                    status = '❌ ОТКРЫТ'
                    risk = danger_risk
                else:
                    status = '⚠ ОТКРЫТ'
                    risk = danger_risk
            else:
                status = '✅ ЗАКРЫТ'
                risk = 'Порт недоступен'

            results.append({
                'port': port,
                'service': service,
                'status': status,
                'risk': risk,
                'open': is_open,
                'dangerous': dangerous
            })
        except Exception:
            results.append({
                'port': port,
                'service': service,
                'status': '✅ ЗАКРЫТ',
                'risk': 'Порт недоступен',
                'open': False,
                'dangerous': dangerous
            })

    return results


def detect_technologies(headers, html):
    techs = []
    hdr_lower = {k.lower(): v for k, v in headers.items()}

    server = hdr_lower.get('server', '').lower()
    if 'nginx' in server:
        techs.append({'name': 'Nginx', 'type': 'Веб-сервер', 'risk': 'Узнаваемая сигнатура',
                      'exploit': 'Поиск уязвимостей версии', 'fix': 'Скройте версию'})
    elif 'apache' in server:
        techs.append({'name': 'Apache', 'type': 'Веб-сервер', 'risk': 'Узнаваемая сигнатура',
                      'exploit': 'Поиск уязвимостей версии', 'fix': 'Скройте версию'})
    elif 'iis' in server:
        techs.append({'name': 'IIS', 'type': 'Веб-сервер', 'risk': 'Узнаваемая сигнатура',
                      'exploit': 'Поиск уязвимостей версии', 'fix': 'Скройте версию'})

    if 'x-powered-by' in hdr_lower:
        powered = hdr_lower['x-powered-by']
        techs.append({'name': powered, 'type': 'Бэкенд', 'risk': 'Раскрытие технологий',
                      'exploit': 'Таргетированные атаки', 'fix': 'Удалите заголовок X-Powered-By'})

    html_lower = html.lower()

    if 'wp-content' in html_lower or 'wp-includes' in html_lower:
        techs.append({'name': 'WordPress', 'type': 'CMS', 'risk': 'Уязвимости плагинов',
                      'exploit': 'Брутфорс /wp-admin', 'fix': 'Обновляйте ядро и плагины'})

    if 'jquery' in html_lower:
        techs.append({'name': 'jQuery', 'type': 'JS-библиотека', 'risk': 'Устаревшие версии',
                      'exploit': 'XSS через старые версии', 'fix': 'Обновите до последней версии'})

    if 'react' in html_lower or '__react' in html_lower:
        techs.append({'name': 'React', 'type': 'JS-фреймворк', 'risk': 'Минимальный',
                      'exploit': 'XSS при небезопасном dangerouslySetInnerHTML',
                      'fix': 'Избегайте dangerouslySetInnerHTML'})

    if 'drupal' in html_lower or '/sites/default/files' in html_lower:
        techs.append({'name': 'Drupal', 'type': 'CMS', 'risk': 'Уязвимости модулей',
                      'exploit': 'Drupalgeddon-атаки', 'fix': 'Обновляйте ядро и модули'})

    return techs


def find_info_leaks(base_url, headers, html):
    leaks = []

    # ИСПРАВЛЕНО: разделены чувствительные и публичные пути
    sensitive_paths = [
        '/.git/config',
        '/.env',
        '/backup.zip',
        '/wp-config.php.bak',
        '/phpinfo.php',
        '/server-status',
        '/.DS_Store',
    ]

    # Публичные пути — их наличие не является утечкой
    public_paths = [
        '/robots.txt',
        '/sitemap.xml',
    ]

    for path in sensitive_paths:
        try:
            resp = requests.get(base_url + path, timeout=3, allow_redirects=False)
            if resp.status_code == 200:
                status = '⚠ УТЕЧКА'
                risk = f'Доступен чувствительный файл: {path}'
            else:
                status = '✅ ЗАЩИЩЁН'
                risk = ''
        except Exception:
            status = '✅ ЗАЩИЩЁН'
            risk = ''

        leaks.append({'path': path, 'status': status, 'risk': risk})

    for path in public_paths:
        try:
            resp = requests.get(base_url + path, timeout=3, allow_redirects=False)
            if resp.status_code == 200:
                status = 'ℹ ПУБЛИЧНЫЙ'
                risk = f'Файл общедоступен (норма): {path}'
            else:
                status = '✅ ОТСУТСТВУЕТ'
                risk = ''
        except Exception:
            status = '✅ ОТСУТСТВУЕТ'
            risk = ''

        leaks.append({'path': path, 'status': status, 'risk': risk})

    # Проверка раскрытия версий в заголовках
    server = headers.get('Server', '')
    if server and any(c.isdigit() for c in server):
        leaks.append({
            'path': 'Заголовок Server',
            'status': '⚠ УТЕЧКА',
            'risk': f'Раскрыта версия: {server}'
        })

    return leaks


def build_backend_protection_tips(security_headers, ports_info, leaks, scheme):
    tips = []

    def steps(*items):
        return '\n'.join(f'{idx}. {item}' for idx, item in enumerate(items, 1))

    missing_headers = [h.get('name') for h in security_headers if '❌' in h.get('status', '')]
    if missing_headers:
        tips.append({
            'name': 'Защитные заголовки в Flask',
            'status': '❌ ТРЕБУЕТСЯ',
            'risk': f"Отсутствуют: {', '.join(missing_headers)}",
            'exploit': 'XSS, clickjacking, утечка метаданных',
            'fix': steps(
                "Создайте функцию @app.after_request(response) и возвращайте response в конце",
                "Добавьте CSP: response.headers['Content-Security-Policy'] = \"default-src 'self'\"",
                "Добавьте HSTS: response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
                "Добавьте X-Frame-Options='DENY' и X-Content-Type-Options='nosniff'",
                "Перезапустите сервер и проверьте заголовки через DevTools -> Network -> Headers"
            )
        })
    else:
        tips.append({
            'name': 'Защитные заголовки в Flask',
            'status': '✅ НАСТРОЕНО',
            'risk': 'Критичных пробелов не обнаружено',
            'exploit': '',
            'fix': ''
        })

    dangerous_open_ports = [str(p.get('port')) for p in ports_info if p.get('open') and p.get('dangerous')]
    if dangerous_open_ports:
        tips.append({
            'name': 'Сетевой периметр backend',
            'status': '❌ ТРЕБУЕТСЯ',
            'risk': f"Открыты опасные порты: {', '.join(dangerous_open_ports)}",
            'exploit': 'Прямой доступ к сервисам БД/админки',
            'fix': steps(
                "Оставьте снаружи только 80/443 (или только 443), остальные порты закройте",
                "Для Linux настройте ufw или iptables, для облака - Security Group",
                "БД (3306/5432/27017/6379) разрешайте только с внутреннего IP сервера",
                "Проверьте, что сервисы слушают 127.0.0.1, если внешний доступ не нужен",
                "После изменений повторно запустите скан и убедитесь, что опасные порты закрыты"
            )
        })
    else:
        tips.append({
            'name': 'Сетевой периметр backend',
            'status': '✅ НАСТРОЕНО',
            'risk': 'Опасные внешние порты не обнаружены',
            'exploit': '',
            'fix': ''
        })

    has_sensitive_leaks = any('УТЕЧКА' in str(l.get('status', '')) for l in leaks)
    tips.append({
        'name': 'Секреты и конфигурация Python',
        'status': '❌ ТРЕБУЕТСЯ' if has_sensitive_leaks else '✅ НАСТРОЕНО',
        'risk': 'Обнаружены утечки чувствительных файлов' if has_sensitive_leaks else 'Явных утечек секретов не найдено',
        'exploit': 'Компрометация токенов, ключей, паролей',
        'fix': steps(
            "Уберите секреты из кода: пароли, токены, ключи не храните в .py файлах",
            "Используйте переменные окружения: os.getenv('DB_PASSWORD')",
            "Добавьте .env и backup-файлы в .gitignore",
            "Запретите выдачу /.env, /.git и backup-файлов на уровне веб-сервера",
            "Смените все ключи, которые могли уже утечь"
        )
    })

    tips.append({
        'name': 'Аутентификация и brute-force защита',
        'status': '⚠ РЕКОМЕНДАЦИЯ',
        'risk': 'Подбор паролей и токенов',
        'exploit': 'Массовые попытки входа',
        'fix': steps(
            "Установите Flask-Limiter и ограничьте попытки логина (например, 5 запросов в минуту)",
            "Хешируйте пароли через bcrypt или argon2, не используйте sha256 без соли",
            "Добавьте задержку/блокировку IP после нескольких неудачных входов",
            "Сделайте минимальную длину пароля 10+ символов и проверку сложности",
            "Для админ-панели включите 2FA (TOTP через Google Authenticator)"
        )
    })

    tips.append({
        'name': 'Безопасный запуск Python backend',
        'status': '⚠ РЕКОМЕНДАЦИЯ',
        'risk': 'Debug-режим, отсутствие TLS и избыточные права процесса',
        'exploit': 'Раскрытие внутренней информации и повышение ущерба',
        'fix': steps(
            "Не запускайте production через app.run(..., debug=True)",
            "Используйте gunicorn/uvicorn + reverse proxy (nginx/caddy)",
            "Запускайте backend от отдельного пользователя без прав root",
            "Отключите подробные traceback-ошибки для пользователя",
            "Включите централизованные логи и алерты по 4xx/5xx"
        )
    })

    if scheme != 'https':
        tips.append({
            'name': 'Шифрование трафика API',
            'status': '❌ ТРЕБУЕТСЯ',
            'risk': 'Передача данных по незашифрованному HTTP',
            'exploit': 'Перехват данных (MITM)',
            'fix': steps(
                "Получите TLS-сертификат (Let's Encrypt или Cloudflare Origin Certificate)",
                "Настройте HTTPS на nginx/caddy и проксируйте трафик в Flask",
                "Сделайте редирект с HTTP на HTTPS (301)",
                "Добавьте HSTS заголовок после проверки HTTPS",
                "Проверьте SSL Labs и повторите скан"
            )
        })

    return tips


def build_human_advice(risk_level, security_headers, ports_info, leaks, scheme):
    missing_headers = [h.get('name') for h in security_headers if '❌' in h.get('status', '')]
    dangerous_ports = [str(p.get('port')) for p in ports_info if p.get('open') and p.get('dangerous')]
    leak_paths = [l.get('path') for l in leaks if 'УТЕЧКА' in str(l.get('status', ''))]

    bad_headers = len(missing_headers)
    open_ports = len(dangerous_ports)
    leak_count = len(leak_paths)

    owner_points = []

    if risk_level == 'КРИТИЧЕСКИЙ':
        owner_urgency = 'Срочность: высокая. До исправления ограничьте вход в админку по IP и сделайте резервную копию.'
    elif risk_level == 'ВЫСОКИЙ':
        owner_urgency = 'Срочность: выше средней. Желательно закрыть основные риски в ближайшие 24-48 часов.'
    elif risk_level == 'СРЕДНИЙ':
        owner_urgency = 'Срочность: средняя. Исправьте замечания планово, но не откладывайте надолго.'
    else:
        owner_urgency = 'Срочность: низкая. Критичных проблем не видно, продолжайте регулярные проверки.'

    owner_points.append(owner_urgency)
    owner_points.append(
        f'Фактически найдено: отсутствуют заголовки={bad_headers}, открыты опасные порты={open_ports}, утечки={leak_count}.'
    )

    if missing_headers:
        owner_points.append(
            f"Какие заголовки нужно добавить: {', '.join(missing_headers[:4])}"
            + (' и другие.' if len(missing_headers) > 4 else '.')
        )
    else:
        owner_points.append('Заголовки защиты в основном порядке: критичных пропусков не найдено.')

    if dangerous_ports:
        owner_points.append(
            f"Какие порты сейчас опасно открыты: {', '.join(dangerous_ports)}. Их стоит закрыть с внешней сети в первую очередь."
        )
    else:
        owner_points.append('Опасные внешние порты не обнаружены.')

    if leak_paths:
        owner_points.append(
            f"Какие утечки найдены: {', '.join(leak_paths[:3])}"
            + (' и другие.' if len(leak_paths) > 3 else '.')
        )
    else:
        owner_points.append('Явных утечек чувствительных файлов не найдено.')

    if scheme != 'https':
        owner_points.append('Сайт открыт по HTTP: включите HTTPS как приоритет №1, иначе данные можно перехватить.')
    else:
        owner_points.append('Сайт открыт по HTTPS: это правильно, поддерживайте сертификат в актуальном состоянии.')

    owner_points.append('Что делать дальше: устраните 1-2 самых критичных пункта и повторно запустите скан.')

    visitor_points = [
        'Перед входом на сайт проверьте адрес: без ошибок в названии и без странных символов.',
        'Если сайт просит срочно перевести деньги, сообщить SMS-код или пароль - это почти всегда обман.',
        'При сомнениях закройте страницу и зайдите на сайт вручную через поисковик или закладки.',
        'Для покупок лучше использовать отдельную карту с небольшим лимитом.'
    ]

    if scheme != 'https':
        visitor_points.insert(1, 'У этого сайта нет HTTPS: не вводите пароль, номер карты и паспортные данные.')
    else:
        visitor_points.insert(1, 'У сайта есть HTTPS, но все равно не вводите коды из SMS и секретные данные по просьбе в чате.')

    if leak_count > 0:
        visitor_points.append('Обнаружены утечки на стороне сайта: для оплаты лучше выбрать другой сайт до исправления.')
    elif open_ports > 0 or bad_headers > 0:
        visitor_points.append('Есть технические проблемы: лучше ограничиться просмотром, без ввода платежных данных.')
    else:
        visitor_points.append('Критичных сигналов не найдено: можно пользоваться, но сохраняйте обычную осторожность.')

    if risk_level in ('КРИТИЧЕСКИЙ', 'ВЫСОКИЙ'):
        visitor_verdict = (
            'Осторожно: по техническим признакам риск повышен. Лучше ничего не оплачивать, '
            'пока владелец не исправит проблемы.'
        )
    elif risk_level == 'СРЕДНИЙ':
        visitor_verdict = (
            'Умеренный риск: можно просматривать сайт, но важные данные вводить только при уверенности и HTTPS.'
        )
    else:
        visitor_verdict = (
            'Сейчас явных критичных проблем не видно, но базовые правила безопасности все равно соблюдайте.'
        )

    return {
        'risk_level': risk_level,
        'owner': owner_points,
        'visitor': visitor_points,
        'visitor_verdict': visitor_verdict
    }


if __name__ == '__main__':
    print("Сервер запущен на http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)