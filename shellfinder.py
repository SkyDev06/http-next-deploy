#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import urllib3
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from datetime import datetime
import os

# Matikan peringatan SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# COLOR GRADING
# ============================================================
class Colors:
    BLACK = '\033[0;30m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ============================================================
# TELEGRAM NOTIFICATION CLASS
# ============================================================
class TelegramNotifier:
    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        
    def send_message(self, message, parse_mode='HTML'):
        try:
            url = f"{self.base_url}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': parse_mode,
                'disable_web_page_preview': True
            }
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                return True, "OK"
            else:
                return False, f"Error: {response.text}"
        except Exception as e:
            return False, str(e)
    
    def send_shell_found(self, url, endpoint, confirm, status_code, timestamp, response_preview=""):
        message = f"""
<b>🔴 SHELL FOUND!</b>

<b>URL:</b> <code>{url}</code>
<b>Endpoint:</b> <code>{endpoint}</code>
<b>Status Code:</b> {status_code}
<b>Keyword:</b> <code>{confirm}</code>
<b>Timestamp:</b> {timestamp}
<b>Response Preview:</b> <code>{response_preview[:200]}...</code>

<i>⚠️ Segera lakukan tindakan!</i>
"""
        return self.send_message(message)
    
    def send_summary(self, stats):
        message = f"""
<b>📊 SCAN COMPLETED</b>

<b>Total URLs:</b> {stats['total_urls']}
<b>Total Endpoints:</b> {stats['total_endpoints']}
<b>Total Checks:</b> {stats['total_checks']}
<b>Found Shells:</b> <b>{stats['found']}</b>
<b>Errors:</b> {stats['errors']}
<b>Elapsed Time:</b> {stats['elapsed']:.2f} detik
<b>Output File:</b> <code>{stats['output_file'] if stats['output_file'] else '-'}</code>

<b>Found URLs:</b>
{chr(10).join([f"• <code>{url}</code>" for url in stats['found_urls'][:10]]) if stats['found_urls'] else '• Tidak ada'}

{stats['found'] if stats['found'] > 0 else '✅ Tidak ada'} shell ditemukan.
"""
        return self.send_message(message)

# ============================================================
# FUNGSI UTAMA
# ============================================================

def print_colored(text, color=Colors.WHITE, bold=False, bg=None, end='\n'):
    style = Colors.BOLD if bold else ''
    bg_color = bg if bg else ''
    print(f"{style}{bg_color}{color}{text}{Colors.RESET}", end=end)

def print_header():
    print_colored("="*70, Colors.CYAN, bold=True)
    print_colored("   SHELL FINDER - Multi-Endpoint with Telegram", Colors.BOLD_CYAN, bold=True)
    print_colored("   Created by: Security Tools", Colors.CYAN)
    print_colored("   Date: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), Colors.CYAN)
    print_colored("="*70, Colors.CYAN, bold=True)

def print_stats(statistik):
    print_colored("\n" + "="*70, Colors.MAGENTA, bold=True)
    print_colored("   STATISTIK SCAN", Colors.BOLD_MAGENTA, bold=True)
    print_colored("="*70, Colors.MAGENTA, bold=True)
    print_colored(f"  Total URL        : {statistik['total_urls']}", Colors.WHITE)
    print_colored(f"  Total Endpoint   : {statistik['total_endpoints']}", Colors.WHITE)
    print_colored(f"  Total Percobaan  : {statistik['total_checks']}", Colors.WHITE)
    print_colored(f"  Ditemukan        : {statistik['found']}", Colors.GREEN, bold=True)
    print_colored(f"  Gagal/Error      : {statistik['errors']}", Colors.RED)
    print_colored(f"  Waktu Eksekusi   : {statistik['elapsed']:.2f} detik", Colors.YELLOW)
    print_colored(f"  Rata-rata/request: {statistik['avg_time']:.2f} detik", Colors.YELLOW)
    if statistik.get('telegram'):
        print_colored(f"  Telegram Status  : {'✅ Aktif' if statistik['telegram'] else '❌ Nonaktif'}", 
                     Colors.GREEN if statistik['telegram'] else Colors.RED)
    print_colored("="*70, Colors.MAGENTA, bold=True)

def baca_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_colored(f"[!] Gagal membaca file {path}: {e}", Colors.RED, bold=True)
        return []

def dapatkan_url():
    print_colored("\n--- SUMBER URL ---", Colors.BOLD_YELLOW)
    print_colored("1. Masukkan satu URL (contoh: http://example.com)", Colors.WHITE)
    print_colored("2. Masukkan file daftar URL (satu per baris)", Colors.WHITE)
    pilihan = input(Colors.CYAN + "Pilih (1/2): " + Colors.RESET).strip()
    if pilihan == '1':
        url = input(Colors.CYAN + "URL: " + Colors.RESET).strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return [url]
    elif pilihan == '2':
        path = input(Colors.CYAN + "Path file daftar URL: " + Colors.RESET).strip()
        urls = baca_file(path)
        if not urls:
            print_colored("[!] Tidak ada URL yang valid!", Colors.RED, bold=True)
            sys.exit(1)
        return urls
    else:
        print_colored("[!] Pilihan tidak valid.", Colors.RED, bold=True)
        sys.exit(1)

def dapatkan_endpoint_multi():
    """Mendukung multiple endpoint files."""
    print_colored("\n--- SUMBER ENDPOINT (MULTI) ---", Colors.BOLD_YELLOW)
    print_colored("1. Masukkan satu endpoint (contoh: /shell.php)", Colors.WHITE)
    print_colored("2. Masukkan file daftar endpoint (satu per baris)", Colors.WHITE)
    print_colored("3. Masukkan MULTIPLE file endpoint (pisahkan dengan koma)", Colors.WHITE)
    print_colored("4. Masukkan MANUAL multiple endpoint (contoh: /shell.php,/admin/cmd.asp)", Colors.WHITE)
    
    pilihan = input(Colors.CYAN + "Pilih (1/2/3/4): " + Colors.RESET).strip()
    endpoints = []
    
    if pilihan == '1':
        ep = input(Colors.CYAN + "Endpoint: " + Colors.RESET).strip()
        if not ep.startswith('/'):
            ep = '/' + ep
        endpoints.append(ep)
    
    elif pilihan == '2':
        path = input(Colors.CYAN + "Path file daftar endpoint: " + Colors.RESET).strip()
        eps = baca_file(path)
        endpoints.extend([ep if ep.startswith('/') else '/' + ep for ep in eps])
    
    elif pilihan == '3':
        files_input = input(Colors.CYAN + "Path file endpoint (pisahkan dengan koma, contoh: eps1.txt,eps2.txt): " + Colors.RESET).strip()
        files = [f.strip() for f in files_input.split(',') if f.strip()]
        for file_path in files:
            eps = baca_file(file_path)
            if eps:
                print_colored(f"[+] Loaded {len(eps)} endpoints from {file_path}", Colors.GREEN)
                endpoints.extend([ep if ep.startswith('/') else '/' + ep for ep in eps])
            else:
                print_colored(f"[-] File {file_path} kosong atau tidak ditemukan", Colors.YELLOW)
    
    elif pilihan == '4':
        eps_input = input(Colors.CYAN + "Masukkan endpoints (pisahkan dengan koma, contoh: /shell.php,/admin/cmd.asp): " + Colors.RESET).strip()
        eps = [e.strip() for e in eps_input.split(',') if e.strip()]
        endpoints.extend([ep if ep.startswith('/') else '/' + ep for ep in eps])
    
    else:
        print_colored("[!] Pilihan tidak valid.", Colors.RED, bold=True)
        sys.exit(1)
    
    if not endpoints:
        print_colored("[!] Tidak ada endpoint yang valid!", Colors.RED, bold=True)
        sys.exit(1)
    
    # Hapus duplikat
    endpoints = list(dict.fromkeys(endpoints))
    print_colored(f"[+] Total endpoint unik: {len(endpoints)}", Colors.GREEN)
    return endpoints

def cek_shell(url, endpoint, confirm, timeout=10, check_status_code=True):
    """Cek apakah endpoint mengandung string konfirmasi."""
    full = urljoin(url, endpoint)
    try:
        resp = requests.get(full, headers={'User-Agent': USER_AGENT},
                            timeout=timeout, allow_redirects=False,
                            verify=False)
        if check_status_code:
            if resp.status_code == 200 and confirm.lower() in resp.text.lower():
                return True, full, resp.status_code, resp.text[:500]
            else:
                return False, full, resp.status_code, None
        else:
            if confirm.lower() in resp.text.lower():
                return True, full, resp.status_code, resp.text[:500]
            else:
                return False, full, resp.status_code, None
    except requests.exceptions.Timeout:
        return False, full, None, "Timeout"
    except requests.exceptions.ConnectionError:
        return False, full, None, "Connection Error"
    except Exception as e:
        return False, full, None, str(e)[:60]

def proses_scan(url, endpoints, confirm, timeout, verbose, results, stats, lock, telegram, output_file, check_status):
    """Proses scanning untuk satu URL terhadap semua endpoint."""
    for endpoint in endpoints:
        found, full, status, response = cek_shell(url, endpoint, confirm, timeout, check_status)
        with lock:
            stats['total_checks'] += 1
            if found:
                stats['found'] += 1
                stats['found_urls'].append(full)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Print ke console
                print_colored(f"\n[+] DITEMUKAN: {full}", Colors.GREEN, bold=True)
                print_colored(f"    Status: {status}", Colors.GREEN)
                print_colored(f"    Endpoint: {endpoint}", Colors.GREEN)
                print_colored(f"    Time: {timestamp}", Colors.GREEN)
                
                # Simpan ke file
                if output_file:
                    output_file.write(f"[{timestamp}] {full}\n")
                    output_file.flush()
                
                # Kirim ke Telegram
                if telegram:
                    success, msg = telegram.send_shell_found(full, endpoint, confirm, status, timestamp, response)
                    if success:
                        print_colored("    📨 Telegram: ✅ Terkirim", Colors.GREEN)
                    else:
                        print_colored(f"    📨 Telegram: ❌ Gagal - {msg}", Colors.RED)
            
            # Progress indicator
            if stats['total_checks'] % 10 == 0:
                sys.stdout.write(f"\r[*] Progres: {stats['total_checks']} dicoba, ditemukan: {stats['found']}")
                sys.stdout.flush()

def main():
    # Header
    print_header()
    
    # User-Agent
    global USER_AGENT
    USER_AGENT = input(Colors.CYAN + "\nUser-Agent (default: Mozilla/5.0): " + Colors.RESET).strip()
    if not USER_AGENT:
        USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # Input data
    urls = dapatkan_url()
    endpoints = dapatkan_endpoint_multi()
    confirm = input(Colors.CYAN + "\nMasukkan HTML keyword konfirmasi: " + Colors.RESET).strip()
    if not confirm:
        print_colored("[!] Keyword tidak boleh kosong.", Colors.RED, bold=True)
        sys.exit(1)

    # Opsi status code
    check_status = input(Colors.CYAN + "Hanya periksa status 200? (y/n, default y): " + Colors.RESET).strip().lower() != 'n'

    # Opsi Telegram
    print_colored("\n--- TELEGRAM NOTIFICATION ---", Colors.BOLD_YELLOW)
    enable_telegram = input(Colors.CYAN + "Aktifkan Telegram notification? (y/n, default n): " + Colors.RESET).strip().lower() == 'y'
    telegram = None
    if enable_telegram:
        bot_token = input(Colors.CYAN + "Bot Token: " + Colors.RESET).strip()
        chat_id = input(Colors.CYAN + "Chat ID: " + Colors.RESET).strip()
        if bot_token and chat_id:
            telegram = TelegramNotifier(bot_token, chat_id)
            print_colored("[*] Testing Telegram connection...", Colors.BLUE)
            success, msg = telegram.send_message("<b>✅ Shell Finder Started!</b>\nMulti-Endpoint Scan dimulai...")
            if success:
                print_colored("[+] Telegram connected!", Colors.GREEN, bold=True)
            else:
                print_colored(f"[!] Telegram failed: {msg}", Colors.RED, bold=True)
                telegram = None
        else:
            print_colored("[!] Bot Token dan Chat ID harus diisi!", Colors.RED, bold=True)

    # Opsi lain
    try:
        timeout = int(input(Colors.CYAN + "\nTimeout per request (detik, default 10): " + Colors.RESET).strip() or "10")
    except:
        timeout = 10

    try:
        threads = int(input(Colors.CYAN + "Jumlah threads (default 20): " + Colors.RESET).strip() or "20")
    except:
        threads = 20

    verbose = input(Colors.CYAN + "Tampilkan proses detail? (y/n, default n): " + Colors.RESET).strip().lower() == 'y'
    simpan = input(Colors.CYAN + "Simpan hasil ke file? (y/n, default n): " + Colors.RESET).strip().lower() == 'y'
    output_file = None
    output_filename = None
    if simpan:
        output_filename = input(Colors.CYAN + "Nama file output: " + Colors.RESET).strip()
        if output_filename:
            output_file = open(output_filename, 'w', encoding='utf-8')
            output_file.write(f"# Shell Finder Results - Multi-Endpoint\n")
            output_file.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output_file.write(f"# Keyword: '{confirm}'\n")
            output_file.write(f"# Total Endpoints: {len(endpoints)}\n\n")

    # Statistik
    stats = {
        'total_urls': len(urls),
        'total_endpoints': len(endpoints),
        'total_checks': 0,
        'found': 0,
        'errors': 0,
        'elapsed': 0,
        'avg_time': 0,
        'telegram': bool(telegram),
        'telegram_status': 'Aktif' if telegram else 'Nonaktif',
        'found_urls': [],
        'output_file': output_filename
    }
    results = []
    lock = threading.Lock()
    start_time = time.time()

    print_colored("\n[+] Memulai scanning dengan threading...", Colors.BOLD_GREEN)
    print_colored(f"[+] Threads: {threads}", Colors.GREEN)
    print_colored(f"[+] Total URL: {len(urls)}", Colors.GREEN)
    print_colored(f"[+] Total Endpoint: {len(endpoints)}", Colors.GREEN)
    print_colored(f"[+] Total Kombinasi: {len(urls) * len(endpoints)}", Colors.GREEN)
    print_colored(f"[+] Konfirmasi: '{confirm}'", Colors.GREEN)
    print_colored(f"[+] Check Status 200: {'Ya' if check_status else 'Tidak'}", Colors.GREEN)
    if telegram:
        print_colored(f"[+] Telegram: ✅ Aktif", Colors.GREEN)
    print_colored("-"*70, Colors.CYAN)

    # Eksekusi dengan ThreadPoolExecutor
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for url in urls:
                future = executor.submit(proses_scan, url, endpoints, confirm, timeout, verbose, results, stats, lock, telegram, output_file, check_status)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print_colored(f"[!] Error dalam thread: {e}", Colors.RED, bold=True)

    except KeyboardInterrupt:
        print_colored("\n\n[!] Dihentikan oleh pengguna.", Colors.RED, bold=True)
        executor.shutdown(wait=False, cancel_futures=True)

    # Hitung waktu
    elapsed = time.time() - start_time
    stats['elapsed'] = elapsed
    if stats['total_checks'] > 0:
        stats['avg_time'] = elapsed / stats['total_checks']

    # Simpan hasil
    if output_file:
        output_file.close()
        print_colored(f"\n[+] Hasil disimpan di: {output_filename}", Colors.GREEN, bold=True)

    # Tampilkan statistik
    print_stats(stats)

    # Highlight jika ditemukan
    if stats['found'] > 0:
        print_colored(f"\n🔥 DITEMUKAN {stats['found']} SHELL!", Colors.BOLD_RED, bold=True, bg=Colors.BG_RED)
        for i, url in enumerate(stats['found_urls'], 1):
            print_colored(f"  {i}. {url}", Colors.RED)
        
        if telegram:
            success, msg = telegram.send_summary(stats)
            if success:
                print_colored("\n📨 Summary terkirim ke Telegram", Colors.GREEN)
            else:
                print_colored(f"\n📨 Gagal kirim summary: {msg}", Colors.RED)
    else:
        print_colored(f"\n✅ Tidak ditemukan shell.", Colors.GREEN, bold=True)
        if telegram:
            telegram.send_message("✅ Scan multi-endpoint selesai. Tidak ada shell ditemukan.")

    print_colored(f"\n[*] Endpoint yang diuji: {len(endpoints)}", Colors.BLUE)

if __name__ == "__main__":
    main()
