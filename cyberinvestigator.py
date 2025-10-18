#!/usr/bin/env python3
"""
Мощный OSINT инструмент - CyberInvestigator
Автоматизированный сбор информации из открытых источников
"""

import os
import sys
import json
import time
import requests
import socket
import whois
import dns.resolver
import shodan
import argparse
import re
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class CyberInvestigator:
    def __init__(self, shodan_api_key=None, virustotal_api_key=None):
        self.shodan_api = shodan_api_key
        self.vt_api = virustotal_api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    def banner(self):
        print("""
    ╔═══════════════════════════════════════════════╗
    ║              CYBER INVESTIGATOR              ║
    ║           Мощный OSINT инструмент            ║
    ║                                               ║
    ║         Автоматический сбор разведки         ║
    ╚═══════════════════════════════════════════════╝
        """)

    def validate_domain(self, domain):
        """Валидация доменного имени"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return re.match(pattern, domain) is not None

    def validate_ip(self, ip):
        """Валидация IP адреса"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def validate_email(self, email):
        """Валидация email адреса"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def domain_investigation(self, domain):
        """Полная разведка домена"""
        print(f"\n[🔍] Начинаем разведку домена: {domain}")
        
        if not self.validate_domain(domain):
            raise ValueError("Неверный формат домена")
            
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whois_info': {},
            'dns_records': {},
            'subdomains': [],
            'technologies': [],
            'emails': [],
            'social_media': [],
            'metadata': {}
        }
        
        # WHOIS информация
        try:
            print("[ℹ️] Сбор WHOIS информации...")
            whois_info = whois.whois(domain)
            results['whois_info'] = {
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date) if whois_info.creation_date else None,
                'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else None,
                'name_servers': list(whois_info.name_servers) if whois_info.name_servers else [],
                'emails': whois_info.emails if whois_info.emails else [],
                'status': whois_info.status if whois_info.status else []
            }
        except Exception as e:
            print(f"[❌] Ошибка WHOIS: {e}")
            results['whois_info']['error'] = str(e)
        
        # DNS записи
        print("[🌐] Сбор DNS записей...")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['dns_records'][record_type] = [str(r) for r in answers]
            except Exception as e:
                results['dns_records'][record_type] = []
        
        # Поиск поддоменов
        print("[🔎] Поиск поддоменов...")
        results['subdomains'] = self.find_subdomains(domain)
        
        # Определение технологий
        print("[⚙️] Определение используемых технологий...")
        results['technologies'] = self.detect_technologies(domain)
        
        # Поиск email адресов
        print("[📧] Поиск email адресов...")
        results['emails'] = self.find_emails(domain)
        
        # Поиск в социальных сетях
        print("[👥] Поиск в социальных сетях...")
        results['social_media'] = self.search_social_media(domain)
        
        # Дополнительная мета-информация
        results['metadata'] = self.get_domain_metadata(domain)
        
        return results

    def find_subdomains(self, domain, wordlist=None):
        """Поиск поддоменов"""
        if wordlist is None:
            wordlist = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
                       'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 
                       'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 
                       'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 
                       'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
                       'api', 'app', 'cdn', 'cloud', 'store', 'shop', 'blog', 'forum']
        
        subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
                print(f"    [+] Найден поддомен: {full_domain}")
            except socket.gaierror:
                pass
            except Exception as e:
                print(f"    [!] Ошибка при проверке {full_domain}: {e}")
        
        print(f"    [i] Проверка {len(wordlist)} поддоменов...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_subdomain, wordlist)
        
        return subdomains

    def detect_technologies(self, domain):
        """Определение используемых технологий"""
        technologies = []
        urls_to_try = [f"http://{domain}", f"https://{domain}"]
        
        for url in urls_to_try:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Проверка CMS
                if 'wp-content' in response.text or 'wp-includes' in response.text:
                    technologies.append('WordPress')
                if 'joomla' in response.text.lower():
                    technologies.append('Joomla')
                if 'drupal' in response.text.lower():
                    technologies.append('Drupal')
                if 'wordpress' in response.text.lower():
                    technologies.append('WordPress')
                
                # Проверка сервера
                server = response.headers.get('Server', '')
                if server:
                    technologies.append(f'Server: {server}')
                
                # Проверка фреймворков
                if 'react' in response.text.lower():
                    technologies.append('React')
                if 'angular' in response.text.lower():
                    technologies.append('Angular')
                if 'vue' in response.text.lower():
                    technologies.append('Vue.js')
                if 'jquery' in response.text.lower():
                    technologies.append('jQuery')
                
                # Проверка аналитики
                if 'google-analytics.com/ga.js' in response.text:
                    technologies.append('Google Analytics')
                if 'googletagmanager.com/gtm.js' in response.text:
                    technologies.append('Google Tag Manager')
                if 'facebook.com/tr/' in response.text:
                    technologies.append('Facebook Pixel')
                
                # Проверка языков
                if '.php' in response.text:
                    technologies.append('PHP')
                if 'asp.net' in response.text.lower():
                    technologies.append('ASP.NET')
                
                # Проверка CDN
                if 'cloudflare' in response.headers.get('Server', '').lower():
                    technologies.append('CloudFlare')
                
                break  # Если один URL сработал, выходим
                    
            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                print(f"    [!] Ошибка при определении технологий для {url}: {e}")
                continue
        
        return list(set(technologies))

    def find_emails(self, domain):
        """Поиск email адресов на сайте"""
        emails = []
        urls_to_try = [f"http://{domain}", f"https://{domain}"]
        
        for url in urls_to_try:
            try:
                response = self.session.get(url, timeout=10, verify=False)
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, response.text)
                emails.extend([email for email in found_emails if domain in email])
                break
            except:
                continue
        
        return list(set(emails))

    def search_social_media(self, domain):
        """Поиск упоминаний в социальных сетях"""
        social_media = []
        platforms = {
            'twitter': f'https://twitter.com/{domain}',
            'facebook': f'https://facebook.com/{domain}',
            'linkedin': f'https://linkedin.com/company/{domain}',
            'instagram': f'https://instagram.com/{domain}',
            'youtube': f'https://youtube.com/@{domain}',
            'github': f'https://github.com/{domain}'
        }
        
        def check_platform(platform, url):
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code in [200, 301, 302]:
                    social_media.append(f"{platform}: {url}")
                    print(f"    [+] Найдена социальная сеть: {platform}")
            except Exception as e:
                pass
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            for platform, url in platforms.items():
                executor.submit(check_platform, platform, url)
        
        return social_media

    def get_domain_metadata(self, domain):
        """Получение дополнительной мета-информации о домене"""
        metadata = {}
        url = f"https://{domain}"
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Заголовок страницы
            title = soup.find('title')
            if title:
                metadata['title'] = title.text.strip()
            
            # Meta description
            description = soup.find('meta', attrs={'name': 'description'})
            if description:
                metadata['description'] = description.get('content', '').strip()
            
            # Ключевые слова
            keywords = soup.find('meta', attrs={'name': 'keywords'})
            if keywords:
                metadata['keywords'] = keywords.get('content', '').strip()
            
            # Размер страницы
            metadata['page_size'] = len(response.content)
            metadata['response_time'] = response.elapsed.total_seconds()
            
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata

    def ip_investigation(self, ip_address):
        """Разведка IP адреса"""
        print(f"\n[🌐] Начинаем разведку IP: {ip_address}")
        
        if not self.validate_ip(ip_address):
            raise ValueError("Неверный формат IP адреса")
            
        results = {
            'ip': ip_address,
            'timestamp': datetime.now().isoformat(),
            'geo_info': {},
            'shodan_data': {},
            'open_ports': [],
            'reverse_dns': []
        }
        
        # Геолокация
        try:
            print("[🗺️] Получение геолокации...")
            response = self.session.get(f'http://ip-api.com/json/{ip_address}')
            geo_data = response.json()
            if geo_data['status'] == 'success':
                results['geo_info'] = {
                    'country': geo_data.get('country', 'N/A'),
                    'country_code': geo_data.get('countryCode', 'N/A'),
                    'region': geo_data.get('regionName', 'N/A'),
                    'city': geo_data.get('city', 'N/A'),
                    'zip': geo_data.get('zip', 'N/A'),
                    'isp': geo_data.get('isp', 'N/A'),
                    'org': geo_data.get('org', 'N/A'),
                    'as': geo_data.get('as', 'N/A'),
                    'lat': geo_data.get('lat', 'N/A'),
                    'lon': geo_data.get('lon', 'N/A'),
                    'timezone': geo_data.get('timezone', 'N/A')
                }
        except Exception as e:
            print(f"[❌] Ошибка геолокации: {e}")
            results['geo_info']['error'] = str(e)
        
        # Reverse DNS
        try:
            print("[🔁] Поиск reverse DNS...")
            hostname = socket.gethostbyaddr(ip_address)
            results['reverse_dns'] = hostname[0]
        except:
            results['reverse_dns'] = "Не найдено"
        
        # Shodan (если доступен API ключ)
        if self.shodan_api:
            try:
                print("[🔍] Запрос к Shodan...")
                api = shodan.Shodan(self.shodan_api)
                shodan_data = api.host(ip_address)
                results['shodan_data'] = {
                    'ports': shodan_data.get('ports', []),
                    'vulnerabilities': shodan_data.get('vulns', []),
                    'services': [f"{item['port']}/{item['transport']}: {item.get('product', 'Unknown')}" 
                               for item in shodan_data.get('data', [])],
                    'tags': shodan_data.get('tags', []),
                    'hostnames': shodan_data.get('hostnames', [])
                }
            except shodan.APIError as e:
                print(f"[⚠️] Shodan API ошибка: {e}")
                results['shodan_data']['error'] = str(e)
            except Exception as e:
                print(f"[⚠️] Ошибка Shodan: {e}")
                results['shodan_data']['error'] = str(e)
        
        # Сканирование портов
        print("[🔒] Базовое сканирование портов...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443, 3306, 5432, 27017]
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((ip_address, port))
                    if result == 0:
                        results['open_ports'].append(port)
                        print(f"    [+] Открыт порт: {port}")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(scan_port, common_ports)
        
        results['open_ports'].sort()
        
        return results

    def email_investigation(self, email):
        """Разведка email адреса"""
        print(f"\n[📧] Начинаем разведку email: {email}")
        
        if not self.validate_email(email):
            raise ValueError("Неверный формат email адреса")
            
        results = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'breaches': [],
            'social_profiles': [],
            'gravatar': None,
            'domain_info': {}
        }
        
        # Извлечение домена из email
        domain = email.split('@')[1]
        results['domain_info'] = {
            'domain': domain,
            'mx_records': self.get_mx_records(domain)
        }
        
        # Проверка на утечки (базовая имитация)
        try:
            print("[🔓] Проверка на утечки данных...")
            # Здесь можно интегрировать с Have I Been Pwned API
            # Для демонстрации возвращаем пустой список
            results['breaches'] = []
        except Exception as e:
            print(f"[⚠️] Ошибка проверки утечек: {e}")
        
        # Поиск Gravatar
        try:
            print("[🖼️] Поиск Gravatar...")
            hash_object = hashlib.md5(email.lower().encode())
            gravatar_url = f"https://www.gravatar.com/avatar/{hash_object.hexdigest()}?d=404&s=200"
            response = self.session.head(gravatar_url, timeout=5)
            if response.status_code == 200:
                results['gravatar'] = gravatar_url
                print("    [+] Найден Gravatar")
        except Exception as e:
            print(f"    [!] Ошибка Gravatar: {e}")
        
        # Поиск в социальных сетях
        print("[👥] Поиск в социальных сетях...")
        username = email.split('@')[0]
        results['social_profiles'] = self.find_social_profiles(username)
        
        return results

    def get_mx_records(self, domain):
        """Получение MX записей для домена"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(mx.exchange) for mx in mx_records]
        except:
            return []

    def find_social_profiles(self, username):
        """Поиск профилей в социальных сетях по username"""
        social_profiles = []
        platforms = {
            'twitter': f'https://twitter.com/{username}',
            'github': f'https://github.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'keybase': f'https://keybase.io/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'youtube': f'https://youtube.com/@{username}'
        }
        
        def check_profile(platform, url):
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code in [200, 301, 302]:
                    social_profiles.append(f"{platform}: {url}")
                    print(f"    [+] Найден профиль: {platform}")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            for platform, url in platforms.items():
                executor.submit(check_profile, platform, url)
        
        return social_profiles

    def save_report(self, results, filename=None):
        """Сохранение отчета"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if 'domain' in results:
                filename = f"domain_report_{results['domain']}_{timestamp}.json"
            elif 'ip' in results:
                filename = f"ip_report_{results['ip']}_{timestamp}.json"
            elif 'email' in results:
                filename = f"email_report_{results['email'].replace('@', '_at_')}_{timestamp}.json"
            else:
                filename = f"osint_report_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[💾] Отчет сохранен: {filename}")
        return filename

    def print_results(self, results):
        """Красивый вывод результатов"""
        print("\n" + "="*60)
        print("📊 РЕЗУЛЬТАТЫ OSINT РАЗВЕДКИ")
        print("="*60)
        
        if 'domain' in results:
            self._print_domain_results(results)
        elif 'ip' in results:
            self._print_ip_results(results)
        elif 'email' in results:
            self._print_email_results(results)

    def _print_domain_results(self, results):
        """Вывод результатов по домену"""
        print(f"\n🏠 ДОМЕН: {results['domain']}")
        print("-" * 40)
        
        if results['whois_info']:
            print("\n📋 WHOIS информация:")
            for key, value in results['whois_info'].items():
                if value and key != 'error':
                    if isinstance(value, list):
                        print(f"   {key}: {', '.join(value)}")
                    else:
                        print(f"   {key}: {value}")
        
        if results['dns_records']:
            print("\n🌐 DNS записи:")
            for record_type, records in results['dns_records'].items():
                if records:
                    print(f"   {record_type}: {', '.join(records[:3])}")
                    if len(records) > 3:
                        print(f"      ... и еще {len(records) - 3} записей")
        
        if results['subdomains']:
            print(f"\n🔎 Найдено поддоменов ({len(results['subdomains'])}):")
            for subdomain in results['subdomains'][:10]:
                print(f"   • {subdomain}")
            if len(results['subdomains']) > 10:
                print(f"   ... и еще {len(results['subdomains']) - 10}")
        
        if results['technologies']:
            print(f"\n⚙️ Обнаруженные технологии ({len(results['technologies'])}):")
            for tech in results['technologies'][:15]:
                print(f"   • {tech}")
        
        if results['emails']:
            print(f"\n📧 Найденные email ({len(results['emails'])}):")
            for email in results['emails']:
                print(f"   • {email}")
        
        if results['social_media']:
            print(f"\n👥 Социальные сети ({len(results['social_media'])}):")
            for social in results['social_media']:
                print(f"   • {social}")
        
        if results.get('metadata'):
            print(f"\n📄 Мета-информация:")
            for key, value in results['metadata'].items():
                if value and key != 'error':
                    print(f"   {key}: {value}")

    def _print_ip_results(self, results):
        """Вывод результатов по IP"""
        print(f"\n🌐 IP АДРЕС: {results['ip']}")
        print("-" * 40)
        
        if results['geo_info']:
            print("\n🗺️ Геолокация:")
            for key, value in results['geo_info'].items():
                if value and value != 'N/A' and key != 'error':
                    print(f"   {key}: {value}")
        
        if results['reverse_dns']:
            print(f"\n🔁 Reverse DNS: {results['reverse_dns']}")
        
        if results['shodan_data']:
            shodan = results['shodan_data']
            if shodan.get('services'):
                print(f"\n🔍 Shodan данные ({len(shodan['services'])} сервисов):")
                for service in shodan['services'][:10]:
                    print(f"   • {service}")
            
            if shodan.get('vulnerabilities'):
                print(f"\n⚠️ Уязвимости ({len(shodan['vulnerabilities'])}):")
                for vuln in shodan['vulnerabilities'][:5]:
                    print(f"   • {vuln}")
        
        if results['open_ports']:
            print(f"\n🔒 Открытые порты ({len(results['open_ports'])}):")
            print(f"   • {', '.join(map(str, results['open_ports']))}")

    def _print_email_results(self, results):
        """Вывод результатов по email"""
        print(f"\n📧 EMAIL: {results['email']}")
        print("-" * 40)
        
        if results['gravatar']:
            print(f"\n🖼️ Gravatar: {results['gravatar']}")
        
        if results['social_profiles']:
            print(f"\n👥 Социальные профили ({len(results['social_profiles'])}):")
            for profile in results['social_profiles']:
                print(f"   • {profile}")
        
        if results['breaches']:
            print(f"\n🔓 Утечки данных ({len(results['breaches'])}):")
            for breach in results['breaches']:
                print(f"   • {breach}")
        else:
            print(f"\n🔓 Утечки данных: не обнаружено (или не проверено)")
        
        if results['domain_info']:
            print(f"\n🌐 Информация о домене:")
            print(f"   • Домен: {results['domain_info']['domain']}")
            if results['domain_info']['mx_records']:
                print(f"   • MX записи: {', '.join(results['domain_info']['mx_records'][:3])}")

def main():
    parser = argparse.ArgumentParser(description='CyberInvestigator - Мощный OSINT инструмент')
    parser.add_argument('-d', '--domain', help='Исследовать домен')
    parser.add_argument('-i', '--ip', help='Исследовать IP адрес')
    parser.add_argument('-e', '--email', help='Исследовать email адрес')
    parser.add_argument('-o', '--output', help='Файл для сохранения отчета')
    parser.add_argument('--shodan', help='Shodan API ключ')
    
    args = parser.parse_args()
    
    investigator = CyberInvestigator(shodan_api_key=args.shodan)
    investigator.banner()
    
    if not any([args.domain, args.ip, args.email]):
        parser.print_help()
        return
    
    try:
        if args.domain:
            results = investigator.domain_investigation(args.domain)
        elif args.ip:
            results = investigator.ip_investigation(args.ip)
        elif args.email:
            results = investigator.email_investigation(args.email)
        
        investigator.print_results(results)
        
        # Сохранение отчета
        if args.output:
            investigator.save_report(results, args.output)
        else:
            investigator.save_report(results)
            
    except KeyboardInterrupt:
        print("\n[⏹️] Операция прервана пользователем")
    except Exception as e:
        print(f"\n[💥] Критическая ошибка: {e}")

if __name__ == "__main__":
    main()
