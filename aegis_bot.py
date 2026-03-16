#!/usr/bin/env python3
"""
AegisScan Telegram Bot
Advanced Web Security Testing Framework - Telegram Interface

Usage: python aegis_bot.py <BOT_TOKEN>
"""

import telebot
from telebot import types
import asyncio
import sys
import os
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import threading
from queue import Queue

# Add project directory to path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from aegisscan import DeepScanner, AsyncHTTPClient
from aegisscan.scanners import (
    SQLiScanner, XSSScanner, CommandInjectionScanner,
    PathTraversalScanner, LFIRFIScanner, SSTIScanner,
    CSRFScanner, OpenRedirectScanner, AuthScanner,
    APISecurityScanner, JWTScanner, FileUploadScanner,
    WebSocketScanner, SSRFScanner, XXEScanner, IDORScanner,
    ComplianceChecker, GraphQLScanner, NoSQLInjectionScanner,
    HTTPSmugglingScanner, WAFBypassScanner, CachePoisoningScanner,
    OAuthOIDCScanner, ClickjackingScanner, LDAPInjectionScanner
)
from aegisscan.recon import (
    EnhancedPortScanner, EnhancedDirectoryBruteforcer,
    SubdomainEnumerator, ServiceTester, SubdomainTakeoverDetector
)
from aegisscan.analyzer import PassiveAnalyzer
from aegisscan.utils.wordlists import WordlistManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Bot token from command line
if len(sys.argv) < 2:
    print("Usage: python aegis_bot.py <BOT_TOKEN>")
    sys.exit(1)

BOT_TOKEN = sys.argv[1]
bot = telebot.TeleBot(BOT_TOKEN, parse_mode='HTML')

# Scan management with thread-safe access
import threading
user_scans = {}  # Track active scans per user
user_scans_lock = threading.Lock()  # Lock for thread-safe access

# Thread pool for concurrent scans
from concurrent.futures import ThreadPoolExecutor
scan_executor = ThreadPoolExecutor(max_workers=10)  # Support up to 10 concurrent scans

# Store running scan threads for cancellation
running_scans = {}  # user_id -> future
running_scans_lock = threading.Lock()

# Scan types mapping
SCAN_TYPES = {
    "deep": {"name": "🔍 Deep Scan", "desc": "Complete comprehensive scan"},
    "normal": {"name": "📡 Normal Scan", "desc": "Standard vulnerability scan"},
    "sqli": {"name": "💉 SQL Injection", "desc": "SQLi testing"},
    "xss": {"name": "⚡ XSS", "desc": "Cross-Site Scripting"},
    "port": {"name": "🚪 Port Scanning", "desc": "Service detection"},
    "directory": {"name": "📁 Directory Bruteforce", "desc": "Path discovery"},
    "subdomain": {"name": "🌐 Subdomain Enumeration", "desc": "DNS discovery"},
    "service": {"name": "🔐 Service Testing", "desc": "Auth & Brute Force"},
    "passive": {"name": "👤 Passive Analysis", "desc": "Security headers"},
    "command": {"name": "💻 Command Injection", "desc": "OS command testing"},
    "path": {"name": "📂 Path Traversal", "desc": "Directory traversal"},
    "lfi": {"name": "📄 LFI/RFI", "desc": "File inclusion testing"},
    "ssti": {"name": "🎨 SSTI", "desc": "Server-Side Template Injection"},
    "csrf": {"name": "🔄 CSRF Analysis", "desc": "Cross-Site Request Forgery"},
    "redirect": {"name": "↩️ Open Redirect", "desc": "Redirect vulnerability"},
    "auth": {"name": "🔑 Auth & Session", "desc": "Authentication testing"},
    "api": {"name": "🔌 API Security", "desc": "API vulnerability testing"},
    "jwt": {"name": "🎫 JWT Security", "desc": "JWT token testing"},
    "upload": {"name": "📤 File Upload", "desc": "Upload vulnerability"},
    "websocket": {"name": "🔊 WebSocket", "desc": "WebSocket security"},
    "ssrf": {"name": "🌍 SSRF", "desc": "Server-Side Request Forgery"},
    "xxe": {"name": "📝 XXE", "desc": "XML External Entity"},
    "idor": {"name": "🔢 IDOR", "desc": "Insecure Direct Object Reference"},
    "compliance": {"name": "✅ Compliance Check", "desc": "OWASP Top 10, PCI-DSS"},
    "graphql": {"name": "◼️ GraphQL Security", "desc": "GraphQL vulnerabilities"},
    "nosql": {"name": "🗄️ NoSQL Injection", "desc": "MongoDB, Redis, etc."},
    "smuggling": {"name": "📦 HTTP Request Smuggling", "desc": "CL.TE, TE.CL attacks"},
    "waf": {"name": "🛡️ WAF Detection & Bypass", "desc": "WAF identification"},
    "cache": {"name": "💾 Cache Poisoning", "desc": "Web cache attacks"},
    "oauth": {"name": "🔓 OAuth/OIDC Security", "desc": "OAuth vulnerabilities"},
    "clickjacking": {"name": "🖱️ Clickjacking", "desc": "X-Frame-Options"},
    "ldap": {"name": "👥 LDAP Injection", "desc": "LDAP vulnerabilities"},
    "takeover": {"name": "🎯 Subdomain Takeover", "desc": "Takeover detection"},
}

# Keyboard builders
def build_main_keyboard():
    """Build main menu keyboard with all scan options"""
    keyboard = types.InlineKeyboardMarkup(row_width=2)
    
    # Group scans into rows of 2
    buttons = []
    for key, value in SCAN_TYPES.items():
        buttons.append(types.InlineKeyboardButton(
            text=value["name"], 
            callback_data=f"scan_{key}"
        ))
    
    # Add buttons in rows of 2
    for i in range(0, len(buttons), 2):
        if i + 1 < len(buttons):
            keyboard.add(buttons[i], buttons[i + 1])
        else:
            keyboard.add(buttons[i])
    
    return keyboard

def build_scan_type_keyboard():
    """Build scan type selection keyboard"""
    keyboard = types.InlineKeyboardMarkup(row_width=2)
    
    keyboard.add(
        types.InlineKeyboardButton("🔍 Deep Scan", callback_data="scan_deep"),
        types.InlineKeyboardButton("📡 Normal Scan", callback_data="scan_normal")
    )
    keyboard.add(
        types.InlineKeyboardButton("💉 SQL Injection", callback_data="scan_sqli"),
        types.InlineKeyboardButton("⚡ XSS", callback_data="scan_xss")
    )
    keyboard.add(
        types.InlineKeyboardButton("🚪 Port Scanning", callback_data="scan_port"),
        types.InlineKeyboardButton("📁 Directory", callback_data="scan_directory")
    )
    keyboard.add(
        types.InlineKeyboardButton("🌐 Subdomain", callback_data="scan_subdomain"),
        types.InlineKeyboardButton("🔐 Service", callback_data="scan_service")
    )
    
    keyboard.add(types.InlineKeyboardButton("📋 Show All Scans", callback_data="show_all"))
    
    return keyboard

def build_back_keyboard():
    """Build back button keyboard"""
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🔙 Back to Menu", callback_data="back_menu"))
    return keyboard

# Message handlers
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """Handle /start and /help commands"""
    user_id = message.from_user.id
    
    welcome_text = """
🔒 <b>AegisScan Security Bot</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ Advanced Web Security Testing Framework

⚠️ <i>WARNING: Use only on systems you have permission to test!</i>

Select a scan type from the menu below:
"""
    
    bot.send_message(
        message.chat.id, 
        welcome_text,
        reply_markup=build_scan_type_keyboard(),
        parse_mode='HTML'
    )

@bot.message_handler(commands=['menu'])
def show_menu(message):
    """Show main menu"""
    send_welcome(message)

@bot.message_handler(commands=['cancel'])
def cancel_scan(message):
    """Cancel current scan"""
    user_id = message.from_user.id
    
    if user_id in user_scans:
        user_scans[user_id]["cancelled"] = True
        bot.reply_to(message, "❌ Scan cancelled!")
    else:
        bot.reply_to(message, "ℹ️ No active scan to cancel.")

@bot.message_handler(commands=['status'])
def scan_status(message):
    """Show scan status"""
    user_id = message.from_user.id
    
    if user_id in user_scans:
        scan_info = user_scans[user_id]
        status_text = f"""
📊 <b>Scan Status</b>
━━━━━━━━━━━━━━━━
🔹 Type: {scan_info.get('type', 'Unknown')}
🔹 Target: {scan_info.get('target', 'Unknown')}
🔹 Status: {scan_info.get('status', 'Running')}
🔹 Started: {scan_info.get('start_time', 'N/A')}
"""
        bot.reply_to(message, status_text, parse_mode='HTML')
    else:
        bot.reply_to(message, "ℹ️ No active scan.")

@bot.message_handler(func=lambda message: True)
def handle_url(message):
    """Handle URL input for scanning"""
    user_id = message.from_user.id
    text = message.text.strip()
    
    # Check if user is waiting for URL
    if user_id in user_scans and user_scans[user_id].get("waiting_url"):
        scan_type = user_scans[user_id].get("scan_type")
        
        # Validate URL
        if not text.startswith(('http://', 'https://')):
            text = 'http://' + text
        
        # Start scan
        user_scans[user_id]["waiting_url"] = False
        user_scans[user_id]["target"] = text
        
        # Notify user
        bot.reply_to(
            message, 
            f"✅ Target set: <code>{text}</code>\n\n🚀 Starting {SCAN_TYPES.get(scan_type, {}).get('name', 'Scan')}...",
            parse_mode='HTML'
        )
        
        # Start scan in background
        start_scan(message.chat.id, user_id, scan_type, text)
    else:
        bot.reply_to(
            message, 
            "👋 Welcome! Use /start to begin scanning.",
            reply_markup=build_scan_type_keyboard()
        )

# Callback query handler
@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    """Handle inline keyboard callbacks"""
    user_id = call.from_user.id
    data = call.data
    
    # Check if there's an active scan
    if user_id in user_scans and user_scans[user_id].get("status") == "Running":
        bot.answer_callback_query(
            call.id, 
            "⚠️ A scan is already in progress! Wait for it to complete or use /cancel",
            show_alert=True
        )
        return
    
    if data == "back_menu":
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text="🔒 <b>AegisScan Security Bot</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n🛡️ Select a scan type:",
            reply_markup=build_main_keyboard(),
            parse_mode='HTML'
        )
        bot.answer_callback_query(call.id)
        
    elif data == "show_all":
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text="🔒 <b>All Scan Types</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n🛡️ Select a scan type:",
            reply_markup=build_main_keyboard(),
            parse_mode='HTML'
        )
        bot.answer_callback_query(call.id)
        
    elif data.startswith("scan_"):
        scan_type = data.replace("scan_", "")
        
        if scan_type not in SCAN_TYPES:
            bot.answer_callback_query(call.id, "❌ Unknown scan type")
            return
        
        # Ask for URL
        scan_info = SCAN_TYPES[scan_type]
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text=f"📍 <b>{scan_info['name']}</b>\n"
                 f"━━━━━━━━━━━━━━━━\n"
                 f"📝 {scan_info['desc']}\n\n"
                 f"🌐 Please enter the target URL:\n"
                 f"<i>Example: https://example.com</i>",
            parse_mode='HTML',
            reply_markup=build_back_keyboard()
        )
        
        # Store user scan info
        user_scans[user_id] = {
            "scan_type": scan_type,
            "waiting_url": True,
            "status": "Waiting",
            "target": None,
            "cancelled": False,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        bot.answer_callback_query(call.id)

# Scan execution
def start_scan(chat_id, user_id, scan_type, target_url):
    """Start scan in background thread"""
    
    # Create output directory
    output_dir = f"scan_results_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    Path(output_dir).mkdir(exist_ok=True)
    
    # Update scan status
    user_scans[user_id]["status"] = "Running"
    user_scans[user_id]["output_dir"] = output_dir
    
    # Send initial message
    progress_msg = bot.send_message(
        chat_id, 
        f"🚀 Starting {SCAN_TYPES[scan_type]['name']} on <code>{target_url}</code>...\n\n"
        f"⏳ Please wait...",
        parse_mode='HTML'
    )
    
    try:
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_scan(scan_type, target_url, output_dir, user_id))
        loop.close()
        
        # Check if cancelled
        if user_scans[user_id].get("cancelled"):
            bot.edit_message_text(
                chat_id=chat_id,
                message_id=progress_msg.message_id,
                text="❌ Scan cancelled by user."
            )
            return
        
        # Format and send results
        send_results(chat_id, user_id, scan_type, target_url, result, output_msg=progress_msg)
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        bot.edit_message_text(
            chat_id=chat_id,
            message_id=progress_msg.message_id,
            text=f"❌ Error during scan:\n<code>{str(e)}</code>",
            parse_mode='HTML'
        )
    finally:
        # Clean up
        user_scans[user_id]["status"] = "Completed"
        user_scans[user_id]["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

async def run_scan(scan_type: str, target_url: str, output_dir: str, user_id: int) -> dict:
    """Run the actual scan"""
    
    http_client = AsyncHTTPClient(
        timeout=60,
        max_redirects=10,
        verify_ssl=True,
        user_agent="AegisScan-TelegramBot/1.0"
    )
    
    wordlist_manager = WordlistManager()
    
    result = {
        "success": False,
        "vulnerabilities": [],
        "discovery": {},
        "message": ""
    }
    
    try:
        # Deep Scan
        if scan_type == "deep":
            scanner = DeepScanner(
                http_client,
                output_dir=output_dir,
                use_external_tools=True,
                auto_install_tools=False
            )
            summary = await scanner.deep_scan(target_url, max_depth=3, max_pages=100)
            result["success"] = True
            result["discovery"] = summary.get("discovery", {})
            result["vulnerabilities"] = summary.get("vulnerabilities", {})
            result["message"] = f"Deep scan completed! Found {summary['vulnerabilities']['total']} vulnerabilities."
            
        # Normal Scan
        elif scan_type == "normal":
            scanner = DeepScanner(
                http_client,
                output_dir=output_dir,
                use_external_tools=False
            )
            summary = await scanner.deep_scan(target_url, max_depth=2, max_pages=50)
            result["success"] = True
            result["discovery"] = summary.get("discovery", {})
            result["vulnerabilities"] = summary.get("vulnerabilities", {})
            result["message"] = f"Normal scan completed! Found {summary['vulnerabilities']['total']} vulnerabilities."
            
        # SQL Injection
        elif scan_type == "sqli":
            scanner = SQLiScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"SQL Injection scan completed! Found {len(vulns)} vulnerabilities."
            
        # XSS
        elif scan_type == "xss":
            scanner = XSSScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"XSS scan completed! Found {len(vulns)} vulnerabilities."
            
        # Port Scanning
        elif scan_type == "port":
            parsed = urlparse(target_url)
            host = parsed.netloc.split(':')[0]
            
            port_scanner = EnhancedPortScanner(wordlist_manager=wordlist_manager)
            ports = await port_scanner.scan_top_ports(host, top_n=100)
            
            result["success"] = True
            result["discovery"]["ports"] = ports
            result["message"] = f"Port scan completed! Found {len(ports)} open ports."
            
        # Directory Bruteforce
        elif scan_type == "directory":
            dir_brute = EnhancedDirectoryBruteforcer(http_client, wordlist_manager=wordlist_manager)
            dirs = await dir_brute.bruteforce(target_url, max_workers=10)
            
            result["success"] = True
            result["discovery"]["directories"] = [{"url": d["url"], "status": d["status_code"]} for d in dirs[:50]]
            result["message"] = f"Directory bruteforce completed! Found {len(dirs)} directories/files."
            
        # Subdomain Enumeration
        elif scan_type == "subdomain":
            parsed = urlparse(target_url)
            domain = parsed.netloc.split(':')[0]
            
            subdomain_enum = SubdomainEnumerator()
            subdomains = await subdomain_enum.enumerate(domain)
            
            result["success"] = True
            result["discovery"]["subdomains"] = subdomains
            result["message"] = f"Subdomain enumeration completed! Found {len(subdomains)} subdomains."
            
        # Service Testing
        elif scan_type == "service":
            parsed = urlparse(target_url)
            host = parsed.netloc.split(':')[0]
            
            # Scan ports first
            port_scanner = EnhancedPortScanner(wordlist_manager=wordlist_manager)
            ports = await port_scanner.scan_top_ports(host, top_n=50)
            
            # Test services
            service_tester = ServiceTester(wordlist_manager=wordlist_manager)
            service_results = []
            
            for port_info in ports:
                service = port_info.get('service', 'unknown')
                if service != 'unknown':
                    test_result = await service_tester.test_service(host, port_info['port'], service)
                    service_results.append(test_result)
            
            result["success"] = True
            result["discovery"]["services"] = service_results
            result["message"] = f"Service testing completed! Tested {len(service_results)} services."
            
        # Passive Analysis
        elif scan_type == "passive":
            passive_analyzer = PassiveAnalyzer(http_client)
            vulns = await passive_analyzer.scan(target_url)
            
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "description": v.description, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Passive analysis completed! Found {len(vulns)} security issues."
            
        # Command Injection
        elif scan_type == "command":
            scanner = CommandInjectionScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Command Injection scan completed! Found {len(vulns)} vulnerabilities."
            
        # Path Traversal
        elif scan_type == "path":
            scanner = PathTraversalScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Path Traversal scan completed! Found {len(vulns)} vulnerabilities."
            
        # LFI/RFI
        elif scan_type == "lfi":
            scanner = LFIRFIScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"LFI/RFI scan completed! Found {len(vulns)} vulnerabilities."
            
        # SSTI
        elif scan_type == "ssti":
            scanner = SSTIScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"SSTI scan completed! Found {len(vulns)} vulnerabilities."
            
        # CSRF
        elif scan_type == "csrf":
            scanner = CSRFScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"CSRF analysis completed! Found {len(vulns)} issues."
            
        # Open Redirect
        elif scan_type == "redirect":
            scanner = OpenRedirectScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Open Redirect scan completed! Found {len(vulns)} vulnerabilities."
            
        # Auth & Session
        elif scan_type == "auth":
            scanner = AuthScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Auth & Session scan completed! Found {len(vulns)} issues."
            
        # API Security
        elif scan_type == "api":
            scanner = APISecurityScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"API Security scan completed! Found {len(vulns)} vulnerabilities."
            
        # JWT Security
        elif scan_type == "jwt":
            scanner = JWTScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"JWT Security scan completed! Found {len(vulns)} issues."
            
        # File Upload
        elif scan_type == "upload":
            scanner = FileUploadScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"File Upload scan completed! Found {len(vulns)} vulnerabilities."
            
        # WebSocket
        elif scan_type == "websocket":
            scanner = WebSocketScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"WebSocket scan completed! Found {len(vulns)} issues."
            
        # SSRF
        elif scan_type == "ssrf":
            scanner = SSRFScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"SSRF scan completed! Found {len(vulns)} vulnerabilities."
            
        # XXE
        elif scan_type == "xxe":
            scanner = XXEScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"XXE scan completed! Found {len(vulns)} vulnerabilities."
            
        # IDOR
        elif scan_type == "idor":
            scanner = IDORScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"IDOR scan completed! Found {len(vulns)} vulnerabilities."
            
        # Compliance
        elif scan_type == "compliance":
            scanner = ComplianceChecker(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "description": v.description, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Compliance check completed! Found {len(vulns)} compliance issues."
            
        # GraphQL
        elif scan_type == "graphql":
            scanner = GraphQLScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"GraphQL Security scan completed! Found {len(vulns)} vulnerabilities."
            
        # NoSQL Injection
        elif scan_type == "nosql":
            scanner = NoSQLInjectionScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"NoSQL Injection scan completed! Found {len(vulns)} vulnerabilities."
            
        # HTTP Smuggling
        elif scan_type == "smuggling":
            scanner = HTTPSmugglingScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"HTTP Request Smuggling scan completed! Found {len(vulns)} vulnerabilities."
            
        # WAF Bypass
        elif scan_type == "waf":
            scanner = WAFBypassScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"WAF Detection & Bypass scan completed! Found {len(vulns)} issues."
            
        # Cache Poisoning
        elif scan_type == "cache":
            scanner = CachePoisoningScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Cache Poisoning scan completed! Found {len(vulns)} vulnerabilities."
            
        # OAuth/OIDC
        elif scan_type == "oauth":
            scanner = OAuthOIDCScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"OAuth/OIDC Security scan completed! Found {len(vulns)} vulnerabilities."
            
        # Clickjacking
        elif scan_type == "clickjacking":
            scanner = ClickjackingScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"Clickjacking scan completed! Found {len(vulns)} vulnerabilities."
            
        # LDAP Injection
        elif scan_type == "ldap":
            scanner = LDAPInjectionScanner(http_client)
            vulns = await scanner.scan(target_url)
            result["success"] = True
            result["vulnerabilities"] = [{"name": v.name, "url": v.url, "severity": str(v.severity)} for v in vulns]
            result["message"] = f"LDAP Injection scan completed! Found {len(vulns)} vulnerabilities."
            
        # Subdomain Takeover
        elif scan_type == "takeover":
            parsed = urlparse(target_url)
            domain = parsed.netloc.split(':')[0]
            
            # First enumerate subdomains
            subdomain_enum = SubdomainEnumerator()
            subdomains = await subdomain_enum.enumerate(domain)
            
            # Check for takeover
            takeover_detector = SubdomainTakeoverDetector(http_client)
            vulnerable = []
            
            for subdomain in subdomains[:20]:  # Limit
                vuln = await takeover_detector.check_subdomain(subdomain)
                if vuln:
                    vulnerable.append({
                        "name": vuln.name,
                        "url": vuln.url,
                        "severity": str(vuln.severity),
                        "description": vuln.description
                    })
            
            result["success"] = True
            result["vulnerabilities"] = vulnerable
            result["discovery"]["subdomains"] = subdomains
            result["message"] = f"Subdomain Takeover scan completed! Checked {len(subdomains[:20])} subdomains, found {len(vulnerable)} vulnerable."
            
        else:
            result["message"] = f"Unknown scan type: {scan_type}"
            
    except Exception as e:
        logger.error(f"Scan error: {e}")
        result["message"] = f"Error: {str(e)}"
        
    finally:
        await http_client.close()
    
    return result

def send_results(chat_id, user_id, scan_type, target_url, result, output_msg):
    """Send scan results to user"""
    
    # Save results to JSON file
    output_dir = user_scans[user_id].get("output_dir", "scan_results")
    result_file = os.path.join(output_dir, "result.json")
    
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump({
            "scan_type": scan_type,
            "target": target_url,
            "result": result
        }, f, indent=2, ensure_ascii=False)
    
    # Build result message
    vuln_count = len(result.get("vulnerabilities", []))
    
    message = f"""
✅ <b>Scan Completed!</b>
━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 <b>Target:</b> <code>{target_url}</code>
🔍 <b>Scan Type:</b> {SCAN_TYPES[scan_type]['name']}
📊 <b>Vulnerabilities Found:</b> {vuln_count}

<i>{result.get('message', '')}</i>
"""
    
    # Add vulnerability summary if any
    if vuln_count > 0:
        message += "\n📋 <b>Vulnerabilities:</b>\n"
        
        # Group by severity
        by_severity = {}
        for v in result["vulnerabilities"]:
            sev = v.get("severity", "Unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        for sev, count in by_severity.items():
            emoji = "🔴" if "CRITICAL" in str(sev).upper() else "🟠" if "HIGH" in str(sev).upper() else "🟡" if "MEDIUM" in str(sev).upper() else "🟢"
            message += f"  {emoji} {sev}: {count}\n"
        
        # Show first few vulnerabilities
        message += "\n"
        for i, v in enumerate(result["vulnerabilities"][:5], 1):
            name = v.get("name", "Unknown")
            url = v.get("url", "N/A")
            message += f"  {i}. {name}\n     📍 {url}\n"
        
        if vuln_count > 5:
            message += f"\n  ... and {vuln_count - 5} more"
    
    # Add discovery info if any
    if result.get("discovery"):
        disc = result["discovery"]
        
        if "ports" in disc:
            message += f"\n🚪 <b>Open Ports:</b> {len(disc['ports'])}"
            for p in disc["ports"][:5]:
                message += f"\n   • Port {p.get('port')}: {p.get('service', 'unknown')}"
                
        if "directories" in disc:
            message += f"\n📁 <b>Directories Found:</b> {len(disc['directories'])}"
            for d in disc["directories"][:5]:
                message += f"\n   • [{d.get('status')}] {d.get('url')}"
                
        if "subdomains" in disc:
            message += f"\n🌐 <b>Subdomains:</b> {len(disc['subdomains'])}"
            for s in disc["subdomains"][:5]:
                message += f"\n   • {s}"
    
    # Add warning
    message += "\n\n⚠️ <i>Results saved for further analysis.</i>"
    
    # Update progress message with results
    try:
        bot.edit_message_text(
            chat_id=chat_id,
            message_id=output_msg.message_id,
            text=message,
            parse_mode='HTML'
        )
    except:
        bot.send_message(chat_id, message, parse_mode='HTML')
    
    # Send JSON file
    try:
        with open(result_file, 'rb') as f:
            bot.send_document(
                chat_id, 
                f, 
                caption=f"📄 Full results for {target_url}"
            )
    except Exception as e:
        logger.error(f"Error sending file: {e}")
    
    # Add menu button
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🔙 Back to Menu", callback_data="back_menu"))
    bot.send_message(chat_id, "Choose an action:", reply_markup=keyboard)

# Main
if __name__ == "__main__":
    logger.info("AegisScan Telegram Bot Starting...")
    logger.info("Bot token: %s", BOT_TOKEN[:10] + "..." + BOT_TOKEN[-5:])
    
    try:
        bot.infinity_polling(timeout=60, long_polling_timeout=60)
    except Exception as e:
        logger.error(f"Bot error: {e}")
        sys.exit(1)

