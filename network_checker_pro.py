#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════╗
║         🔥 Network Checker Pro v4.3                 ║
║    Windows CMD Compatible - Network Scanner Tool     ║
║         For authorized pentesting only               ║
╚══════════════════════════════════════════════════════╝
"""

import socket
import ssl
import random
import ipaddress
import json
import base64
import time
import threading
import concurrent.futures
import sys
import os
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from enum import Enum

# Detect OS
IS_WINDOWS = sys.platform.startswith("win")

# CMD-compatible colors (only for Windows)
if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass

class Cl:
    G = '\033[92m'
    R = '\033[91m'
    Y = '\033[93m'
    B = '\033[94m'
    C = '\033[96m'
    M = '\033[95m'
    BD = '\033[1m'
    D = '\033[2m'
    RS = '\033[0m'
    
    # Disable colors on Windows CMD if issues
    @classmethod
    def init(cls):
        global IS_WINDOWS
        if IS_WINDOWS:
            # Test if ANSI works
            try:
                import colorama
                colorama.init()
            except ImportError:
                # Fallback: no colors
                for attr in ['G','R','Y','B','C','M','BD','D','RS']:
                    setattr(cls, attr, '')

Cl.init()

def col(txt, color):
    return f"{color}{txt}{Cl.RS}"

def pr(txt, color, end="\n"):
    sys.stdout.write(f"{color}{txt}{Cl.RS}{end}")
    sys.stdout.flush()

# Check dnspython
try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ==========================================
# CDN IP RANGES
# ==========================================

CDN_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18",
        "167.82.0.0/17", "199.27.72.0/21", "199.232.0.0/16",
    ],
    "Gcore": [
        "5.188.0.0/19", "5.255.0.0/16", "37.230.112.0/20",
        "87.245.200.0/21", "95.163.0.0/17", "185.6.168.0/22",
        "185.17.184.0/22", "185.128.236.0/22", "95.169.160.0/19",
    ],
    "Netlify": ["75.2.0.0/16", "99.83.0.0/16", "199.60.0.0/16"],
}

# ==========================================
# CONFIG
# ==========================================

@dataclass
class Config:
    target_ports: List[int] = field(default_factory=lambda: [443, 80, 2053, 2083, 2087, 2096, 8443])
    ping_count: int = 4
    ping_timeout: float = 2.0
    max_latency_ms: int = 800
    max_packet_loss_pct: float = 30.0
    workers: int = 200
    
    dns_servers: List[str] = field(default_factory=lambda: [
        "1.1.1.1", "8.8.8.8", "9.9.9.9",
        "208.67.222.222", "185.228.168.9"
    ])
    
    sni_domain: str = "www.google.com"
    sni_list: List[str] = field(default_factory=lambda: [
        "www.google.com", "www.youtube.com", "www.microsoft.com",
        "www.apple.com", "www.cloudflare.com", "www.github.com",
        "www.amazon.com", "www.netflix.com", "www.spotify.com",
        "www.wikipedia.org"
    ])
    
    output_dir: str = "network_checker_results"
    verbose: bool = False

# ==========================================
# DNS MODULE
# ==========================================

class DNSModule:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        if DNS_OK:
            self.r = dns.resolver.Resolver()
            self.r.timeout = 3
            self.r.lifetime = 3
    
    def resolve(self, domain: str, rtype: str = "A") -> List[str]:
        if DNS_OK:
            for s in self.cfg.dns_servers:
                try:
                    self.r.nameservers = [s]
                    ans = self.r.resolve(domain, rtype)
                    return [str(x) for x in ans]
                except:
                    continue
        try:
            return list(set([a[4][0] for a in socket.getaddrinfo(domain, 80, socket.AF_INET)]))
        except:
            return []
    
    def propagation(self, domain: str) -> Dict:
        res = {}
        for s in self.cfg.dns_servers:
            try:
                if DNS_OK:
                    self.r.nameservers = [s]
                    t0 = time.time()
                    ans = self.r.resolve(domain, "A")
                    dt = (time.time()-t0)*1000
                    res[s] = {"ips": [str(x) for x in ans], "latency_ms": round(dt,2), "status": "ok"}
                else:
                    t0 = time.time()
                    ips = self.resolve(domain)
                    dt = (time.time()-t0)*1000
                    res[s] = {"ips": ips, "latency_ms": round(dt,2), "status": "ok" if ips else "fail"}
            except Exception as e:
                st = "timeout" if "timed out" in str(e).lower() else "error"
                res[s] = {"status": st, "latency_ms": None}
        return res
    
    def sub_scan(self, domain: str, wl: List[str]=None) -> Dict[str, List[str]]:
        if wl is None:
            wl = ["www","mail","ftp","admin","blog","shop","cdn","api","app",
                  "test","dev","vpn","ssh","webmail","portal","support","m",
                  "mobile","forum","static","panel","cp","direct","ns1","ns2"]
        res = {}
        t = len(wl)
        for i, s in enumerate(wl):
            f = f"{s}.{domain}"
            ips = self.resolve(f)
            if ips:
                res[f] = ips
            if (i+1)%10==0:
                pct = int(((i+1)/t)*30)
                bar = "#"*pct + "."*(30-pct)
                sys.stdout.write(f"\r  [{bar}] {i+1}/{t} | found: {len(res)}  ")
                sys.stdout.flush()
        print()
        return res
    
    def sni_candidates(self, ip: str) -> List[str]:
        cand = []
        for d in self.cfg.sni_list:
            try:
                if self.resolve(d):
                    cand.append(d)
            except:
                continue
        return cand

# ==========================================
# TCP SCANNER
# ==========================================

class PortScanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
    
    def tcp_ping(self, ip: str, port: int, timeout: float=None) -> Tuple[bool, float]:
        if timeout is None: timeout = self.cfg.ping_timeout
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            r = s.connect_ex((ip, port))
            dt = (time.time()-t0)*1000
            return r==0, round(dt,2)
        except:
            return False, float('inf')
        finally:
            try: s.close()
            except: pass
    
    def multi_ping(self, ip: str, ports: List[int], cnt: int=None) -> Optional[Dict]:
        if cnt is None: cnt = self.cfg.ping_count
        pr = {}
        for p in ports:
            lats, ok, fail = [], 0, 0
            for _ in range(cnt):
                suc, lat = self.tcp_ping(ip, p)
                if suc:
                    lats.append(lat); ok += 1
                else:
                    fail += 1
            total = ok+fail
            if total>0 and ok>0:
                loss = round((fail/total)*100,2)
                avg = round(sum(lats)/len(lats),2) if lats else 0
                st = "open" if loss<self.cfg.max_packet_loss_pct else "unstable"
                pr[p] = {"latency_ms": avg, "loss_pct": loss, "ok": ok, "total": total, "status": st}
        if pr:
            return {
                "ip": ip, "ports": pr,
                "best_port": min(pr, key=lambda p: pr[p]["latency_ms"]),
                "best_latency": min(r["latency_ms"] for r in pr.values()),
                "status": max(r["status"] for r in pr.values())
            }
        return None
    
    def scan_range(self, ips: List[str], ports: List[int]=None) -> List[Dict]:
        if ports is None: ports = self.cfg.target_ports[:3]
        res, total, done = [], len(ips), 0
        pr(f"[*] TCP scan on {len(ports)} ports ({total} IPs)", Cl.C)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg.workers) as ex:
            futs = {ex.submit(self.multi_ping, ip, ports): ip for ip in ips}
            for f in concurrent.futures.as_completed(futs):
                done += 1
                try:
                    r = f.result()
                    if r: res.append(r)
                except: pass
                if done%25==0 or done==total:
                    pct = int((done/total)*40) if total>0 else 0
                    bar = "#"*pct + "."*(40-pct)
                    sys.stdout.write(f"\r  [{bar}] {done}/{total} | found: {len(res)}   ")
                    sys.stdout.flush()
        print()
        return res

# ==========================================
# SSL MODULE
# ==========================================

class SSLModule:
    @staticmethod
    def handshake(ip: str, port: int, sni: str, timeout: float=5.0) -> Optional[Dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            t0 = time.time()
            s.connect((ip, port))
            ss = ctx.wrap_socket(s, server_hostname=sni)
            dt = (time.time()-t0)*1000
            ciph = ss.cipher()
            ver = ss.version()
            try: ss.unwrap()
            except: pass
            s.close()
            return {"handshake_ms": round(dt,2), "cipher": ciph[0] if ciph else "unknown", "protocol": ver, "sni_ok": True}
        except ssl.SSLError as e:
            if "WRONG_VERSION" in str(e): return {"error": "not_ssl", "sni_ok": False}
            return {"error": f"ssl:{str(e)[:40]}", "sni_ok": False}
        except socket.timeout: return {"error": "timeout", "sni_ok": False}
        except Exception as e: return {"error": str(e)[:40], "sni_ok": False}
    
    @staticmethod
    def check_sni(ip: str, sni_list: List[str], port: int=443) -> Dict[str, Dict]:
        res = {}
        for sni in sni_list[:5]:
            res[sni] = SSLModule.handshake(ip, port, sni)
            time.sleep(0.1)
        return res

# ==========================================
# HTTP MODULE
# ==========================================

class HTTPModule:
    @staticmethod
    def check_https(ip: str, port: int, sni: str, path: str="/", timeout: float=5.0) -> Dict:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            ss = ctx.wrap_socket(s, server_hostname=sni)
            req = f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            t0 = time.time()
            ss.sendall(req.encode())
            resp = b""
            while True:
                try:
                    ch = ss.recv(4096)
                    if not ch: break
                    resp += ch
                except socket.timeout: break
                except: break
            dt = (time.time()-t0)*1000
            try: ss.close()
            except: pass
            s.close()
            txt = resp.decode(errors='ignore')
            first = txt.split('\r\n')[0] if txt else ""
            code = 0
            if ' ' in first:
                try: code = int(first.split(' ')[1])
                except: pass
            return {"status": code, "response_ms": round(dt,2), "size": len(resp), "success": 200<=code<400}
        except Exception as e:
            return {"error": str(e)[:50], "success": False}

# ==========================================
# CLEAN IP SCANNER
# ==========================================

class CleanIPScanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.ps = PortScanner(cfg)
    
    def gen_ips(self, provider: str="all", count: int=500) -> List[str]:
        if provider == "all":
            rngs = []
            for p in CDN_RANGES.values(): rngs.extend(p)
        elif provider in CDN_RANGES:
            rngs = CDN_RANGES[provider]
        else:
            pr("[!] Invalid provider", Cl.R)
            return []
        ips, per = [], max(count//len(rngs), 5)
        for c in rngs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                hosts = list(net.hosts())
                if hosts:
                    sel = random.sample(hosts, min(per, len(hosts)))
                    ips.extend(str(ip) for ip in sel)
            except: pass
        random.shuffle(ips)
        return ips[:count]
    
    def scan(self, ips: List[str], sni: str=None) -> List[Dict]:
        if sni is None: sni = self.cfg.sni_domain
        pr("-"*55, Cl.D)
        pr("[*] Clean IP Scan (Full Check)", Cl.C)
        pr(f"    SNI: {sni} | IPs: {len(ips)}", Cl.D)
        pr("-"*55, Cl.D)
        
        clean, total, done = [], len(ips), 0
        lock = threading.Lock()
        
        def check(ip: str) -> Optional[Dict]:
            nonlocal done
            tcp = self.ps.multi_ping(ip, [443], 2)
            if not tcp:
                with lock: done += 1
                return None
            ssl = SSLModule.handshake(ip, 443, sni)
            if not ssl or ssl.get("error"):
                with lock: done += 1
                return None
            http = HTTPModule.check_https(ip, 443, sni)
            if not http.get("success"):
                with lock: done += 1
                return None
            with lock: done += 1
            score = 100.0
            bp = tcp.get("best_port", 443)
            lat = tcp["ports"].get(bp, {}).get("latency_ms", 1000)
            score -= min(lat/5, 40)
            if ssl.get("handshake_ms"): score -= min(ssl["handshake_ms"]/10, 30)
            if ssl.get("protocol")=="TLSv1.3": score += 10
            if http.get("response_ms"): score -= min(http["response_ms"]/20, 20)
            if http.get("status")==200: score += 10
            return {"ip": ip, "tcp": tcp, "ssl": ssl, "http": http, "score": max(score,0)}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg.workers) as ex:
            futs = {ex.submit(check, ip): ip for ip in ips}
            for f in concurrent.futures.as_completed(futs):
                try:
                    r = f.result()
                    if r: clean.append(r)
                except: pass
                with lock: cur = done
                if cur%10==0 or cur>=total:
                    pct = int((cur/total)*30) if total>0 else 0
                    bar = "#"*pct + "."*(30-pct)
                    avg = sum(x["tcp"]["best_latency"] for x in clean[-10:])/max(len(clean[-10:]),1) if clean else 0
                    sys.stdout.write(f"\r  [{bar}] {cur}/{total} | clean: {len(clean)} | avg: {avg:.0f}ms   ")
                    sys.stdout.flush()
        print()
        pr(f"[+] Done. {len(clean)} clean IPs found", Cl.G)
        return sorted(clean, key=lambda x: x["score"], reverse=True)

# ==========================================
# CONFIG GENERATOR
# ==========================================

class ConfigGen:
    def __init__(self, cfg: Config):
        self.cfg = cfg
    
    def shuffle(self, ips: List[str], method: str="random") -> List[str]:
        x = ips.copy()
        if method=="random":
            random.shuffle(x)
        elif method=="reverse":
            x.reverse(); random.shuffle(x)
        elif method=="interleave":
            h = len(x)//2
            a, b = x[:h], x[h:]
            x = []
            for i in range(max(len(a),len(b))):
                if i<len(a): x.append(a[i])
                if i<len(b): x.append(b[i])
        elif method=="block":
            bs = max(5, len(x)//10)
            random.shuffle(x)
            blks = [x[i:i+bs] for i in range(0, len(x), bs)]
            random.shuffle(blks)
            x = [ip for b in blks for ip in b]
        return x
    
    def vless(self, ip: str, sni: str, port: int=443, uid: str=None) -> Dict:
        return {"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":ip,"port":port,"users":[{"id":uid or str(uuid.uuid4()),"encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":sni}}}]}
    
    def vmess(self, ip: str, sni: str, port: int=443, uid: str=None) -> Dict:
        return {"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":ip,"port":port,"users":[{"id":uid or str(uuid.uuid4()),"security":"auto","alterId":0}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":sni}}}]}
    
    def reality(self, ip: str, sni: str, port: int=443, sid: str=None) -> Dict:
        return {"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":ip,"port":port,"users":[{"id":str(uuid.uuid4()),"flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":sni,"fingerprint":"random","shortId":sid or "".join(random.choices("0123456789abcdef",k=8))}}}]}
    
    def link(self, cfg: Dict, proto: str) -> str:
        o = cfg["outbounds"][0]; v = o["settings"]["vnext"][0]
        addr, port, uid = v["address"], v["port"], v["users"][0]["id"]
        if proto=="vless":
            sni = o["streamSettings"]["tlsSettings"]["serverName"]
            return f"vless://{uid}@{addr}:{port}?security=tls&sni={sni}&type=tcp#Pro-{addr}"
        elif proto=="vmess":
            sni = o["streamSettings"]["tlsSettings"]["serverName"]
            obj = {"v":"2","ps":f"Pro-{addr}","add":addr,"port":str(port),"id":uid,"aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"/","tls":"tls","sni":sni}
            return "vmess://"+base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().strip("=")
        elif proto=="reality":
            rs = o["streamSettings"]["realitySettings"]
            return f"vless://{uid}@{addr}:{port}?security=reality&flow=xtls-rprx-vision&sni={rs['serverName']}&type=tcp&fp={rs['fingerprint']}&sid={rs['shortId']}#Pro-Real-{addr}"
        return json.dumps(cfg)
    
    def batch(self, ips: List[str], proto: str="vless", sni: str=None, count: int=10, method: str="random") -> Tuple[List[Dict], List[str]]:
        if sni is None: sni = self.cfg.sni_domain
        x = self.shuffle(ips, method)
        while len(x) < count: x.extend(self.shuffle(ips, "random"))
        cfgs, links = [], []
        for i in range(count):
            ip = x[i%len(x)]
            if proto=="vmess": cfg = self.vmess(ip, sni)
            elif proto=="reality": cfg = self.reality(ip, sni)
            else: cfg = self.vless(ip, sni)
            cfgs.append(cfg); links.append(self.link(cfg, proto))
        return cfgs, links

# ==========================================
# HTML REPORT GENERATOR (PERSIAN OUTPUT)
# ==========================================

class ReportGen:
    def __init__(self, out: str):
        self.out = out
        os.makedirs(out, exist_ok=True)
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def save_json(self, data: Any, name: str) -> str:
        p = os.path.join(self.out, f"{self.ts}_{name}")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return p
    
    def save_txt(self, lines: List[str], name: str) -> str:
        p = os.path.join(self.out, f"{self.ts}_{name}")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return p
    
    def html_report(self, clean: List[Dict], cfgs: List[Dict], proto: str, sni: str) -> str:
        cnt = len(clean)
        best = min((x['tcp']['best_latency'] for x in clean), default=0)
        avg = sum(x['tcp']['best_latency'] for x in clean)/max(cnt,1)
        
        ip_rows = ""
        for i, d in enumerate(clean[:10], 1):
            ssl_ok = "\u2713" if not d['ssl'].get("error") else "\u2717"
            http_st = str(d['http'].get('status','?')) if d['http'].get("success") else "\u2717"
            ip_rows += f"<tr><td>{i}</td><td>{d['ip']}</td><td>{d['tcp']['best_latency']:.1f}ms</td><td class='g'>{ssl_ok}</td><td class='g'>{http_st}</td><td>{d['score']:.1f}</td></tr>\n"
        
        cdiv = ""
        for i, cfg in enumerate(cfgs[:5], 1):
            o = cfg['outbounds'][0]; v = o['settings']['vnext'][0]
            cdiv += f"<div class='cfg'><b>Config {i}:</b> {o['protocol']}://{v['users'][0]['id'][:8]}...@{v['address']}:{v['port']}<pre>{json.dumps(cfg, indent=2)}</pre></div>\n"
        
        html = f"""<!DOCTYPE html>
<html dir='rtl' lang='fa'>
<head>
<meta charset='UTF-8'><title>Network Checker Pro Report</title>
<style>
body{{font-family:Tahoma,'Segoe UI',sans-serif;background:#1a1a2e;color:#eee;margin:20px;}}
h1{{color:#e94560;text-align:center;}}
h2{{color:#0f3460;background:#e94560;padding:10px;border-radius:8px;}}
table{{width:100%;border-collapse:collapse;margin:15px 0;}}
th{{background:#16213e;color:#e94560;padding:10px;}}
td{{border:1px solid #333;padding:8px;text-align:center;}}
tr:nth-child(even){{background:#16213e;}}
.g{{color:#4ecca3;}}
pre{{background:#0f3460;padding:15px;border-radius:8px;overflow-x:auto;}}
.cfg{{background:#16213e;padding:10px;margin:5px 0;border-radius:5px;font-size:12px;}}
</style></head>
<body>
<h1>Network Checker Pro - Report</h1>
<p>Date: {datetime.now().strftime("%Y/%m/%d %H:%M:%S")} | SNI: {sni} | Protocol: {proto}</p>
<h2>Summary</h2>
<table><tr><th>Clean IPs</th><th>Best Latency</th><th>Avg Latency</th><th>Configs</th></tr>
<tr><td>{cnt}</td><td class='g'>{best:.1f}ms</td><td>{avg:.1f}ms</td><td>{len(cfgs)}</td></tr></table>
<h2>Top 10 IPs</h2>
<table><tr><th>#</th><th>IP</th><th>Latency</th><th>SSL</th><th>HTTP</th><th>Score</th></tr>
{ip_rows}</table>
<h2>Generated Configs</h2>
{cdiv}
<p style='text-align:center;color:#666;margin-top:50px;'>Generated by Network Checker Pro - For authorized testing only</p>
</body></html>"""
        
        p = os.path.join(self.out, f"{self.ts}_report.html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(html)
        return p

# ==========================================
# MAIN APP
# ==========================================

class App:
    def __init__(self):
        self.cfg = Config()
        self.dns = DNSModule(self.cfg)
        self.ps = PortScanner(self.cfg)
        self.cs = CleanIPScanner(self.cfg)
        self.cg = ConfigGen(self.cfg)
        self.rp = ReportGen(self.cfg.output_dir)
    
    def banner(self):
        lines = [
            "╔═══════════════════════════════════════════╗",
            "║    Network Checker Pro v4.3 (CMD)        ║",
            "║    Network Scanner & Config Generator    ║",
            "║    For authorized pentesting only        ║",
            "╚═══════════════════════════════════════════╝"
        ]
        for l in lines:
            pr(l, Cl.C)
    
    def menu(self):
        while True:
            print()
            pr("-"*45, Cl.D)
            pr("MAIN MENU:", Cl.BD+Cl.M)
            print("  " + col("1.", Cl.C) + " Clean IP Scan (Full)")
            print("  " + col("2.", Cl.C) + " TCP Port Scan (Fast)")
            print("  " + col("3.", Cl.C) + " DNS & SNI Test")
            print("  " + col("4.", Cl.C) + " Generate Configs from IPs")
            print("  " + col("5.", Cl.C) + " Mixed Mode (All-in-One)")
            print("  " + col("0.", Cl.R) + " Exit")
            ch = input(f"\n  {col('>', Cl.G)} Choice: ").strip()
            if ch == "1": self.m_clean()
            elif ch == "2": self.m_tcp()
            elif ch == "3": self.m_dns()
            elif ch == "4": self.m_config()
            elif ch == "5": self.m_mixed()
            elif ch == "0":
                pr("Goodbye!", Cl.G)
                break
            else:
                pr("[-] Invalid choice", Cl.R)
    
    def m_clean(self):
        print()
        pr("-"*45, Cl.D)
        pr("[*] Clean IP Scan (Full Check)", Cl.BD+Cl.C)
        print("\n  " + col("CDN Provider:", Cl.Y))
        pv = list(CDN_RANGES.keys()) + ["All"]
        for i, p in enumerate(pv, 1):
            print(f"    {col(f'{i}.', Cl.C)} {p}")
        try:
            pc = int(input(f"\n  {col('>', Cl.G)} Select: "))
            prov = pv[pc-1] if 1<=pc<=len(pv) else "All"
        except: prov = "All"
        pk = "all" if prov=="All" else prov
        try: cnt = int(input(f"  {col('>', Cl.G)} IP count [500]: ") or "500")
        except: cnt = 500
        sni = input(f"  {col('>', Cl.G)} SNI [www.google.com]: ") or "www.google.com"
        pr(f"\n  Generating IPs from {prov}...", Cl.Y)
        ips = self.cs.gen_ips(pk, cnt)
        pr(f"  {col('OK', Cl.G)} {len(ips)} IPs generated")
        clean = self.cs.scan(ips, sni)
        if not clean:
            pr("[-] No clean IPs found!", Cl.R)
            input(f"\n  {col('[Enter] back', Cl.D)}")
            return
        self.rp.save_json(clean, "clean_ips.json")
        self.rp.save_txt([x['ip'] for x in clean], "clean_ips.txt")
        print(); pr("-"*45, Cl.D)
        pr("TOP 10 IPs:", Cl.BD+Cl.G)
        print(f"  {'#':<4} {'IP':<16} {'Latency':<10} {'SSL':<8} {'HTTP':<8} {'Score':<8}")
        print(f"  {col('─'*50, Cl.D)}")
        for i, d in enumerate(clean[:10], 1):
            lat = d['tcp']['best_latency']
            lc = Cl.G if lat<200 else (Cl.Y if lat<400 else Cl.R)
            ssl_ok = col("OK", Cl.G) if not d['ssl'].get("error") else col("FAIL", Cl.R)
            http_st = str(d['http'].get('status','?')) if d['http'].get("success") else col("FAIL", Cl.R)
            print(f"  {i:<4} {col(d['ip'], Cl.C):<16} {col(f'{lat:.0f}ms', lc):<10} {ssl_ok:<8} {http_st:<8} {d['score']:.1f}")
        input(f"\n  {col('[Enter] back', Cl.D)}")
    
    def m_tcp(self):
        print(); pr("-"*45, Cl.D)
        pr("[*] TCP Port Scan", Cl.BD+Cl.C)
        inp = input(f"  {col('>', Cl.G)} IP or CIDR range: ")
        try:
            if "/" in inp:
                net = ipaddress.ip_network(inp, strict=False)
                ips = [str(ip) for ip in list(net.hosts())[:1000]]
            else: ips = [inp]
        except Exception as e:
            pr(f"[-] Error: {e}", Cl.R)
            input(f"\n  {col('[Enter] back', Cl.D)}")
            return
        pr(f"  Scanning {len(ips)} IPs...", Cl.Y)
        res = self.ps.scan_range(ips)
        if res:
            self.rp.save_json(res, "tcp_scan.json")
            pr(f"\n  {col('OK', Cl.G)} {len(res)} IPs with open ports")
            for r in res[:5]:
                print(f"    {col(r['ip'], Cl.C)} -> best: {r['best_port']} ({r['best_latency']:.0f}ms)")
        else: pr("[-] Nothing found", Cl.Y)
        input(f"\n  {col('[Enter] back', Cl.D)}")
    
    def m_dns(self):
        print(); pr("-"*45, Cl.D)
        pr("[*] DNS & SNI Test", Cl.BD+Cl.C)
        print("\n  " + col("1.", Cl.C) + " DNS Propagation Check")
        print("  " + col("2.", Cl.C) + " Subdomain Scan")
        print("  " + col("3.", Cl.C) + " Find SNI Candidates")
        ch = input(f"\n  {col('>', Cl.G)} Choice: ")
        if ch == "1":
            d = input(f"  {col('>', Cl.G)} Domain: ")
            res = self.dns.propagation(d)
            print(f"\n  {col('DNS Propagation Results:', Cl.BD)}")
            for s, data in res.items():
                if data['status']=="ok":
                    print(f"    {col(s, Cl.C):<20} -> {col(', '.join(data['ips'][:3]), Cl.G)} ({data['latency_ms']:.0f}ms)")
                else:
                    print(f"    {col(s, Cl.C):<20} -> {col(data['status'], Cl.R)}")
        elif ch == "2":
            d = input(f"  {col('>', Cl.G)} Domain: ")
            res = self.dns.sub_scan(d)
            if res:
                print(f"\n  {col('Found:', Cl.BD)}")
                for sub, ips in res.items():
                    print(f"    {col(sub, Cl.C):<30} -> {', '.join(ips[:2])}")
            else: pr("\n[-] Nothing found", Cl.Y)
        elif ch == "3":
            ip = input(f"  {col('>', Cl.G)} IP: ")
            cand = self.dns.sni_candidates(ip)
            print(f"\n  {col('SNI Candidates:', Cl.BD)}")
            for c in cand: print(f"    {col(c, Cl.C)}")
        input(f"\n  {col('[Enter] back', Cl.D)}")
    
    def m_config(self):
        print(); pr("-"*45, Cl.D)
        pr("[*] Generate Configs from IPs", Cl.BD+Cl.C)
        src = input(f"  {col('>', Cl.G)} Source (1=file / 2=static list): ")
        ips = []
        if src == "1":
            p = input(f"  {col('   Path:', Cl.D)} ")
            try:
                with open(p) as f:
                    ips = [l.strip() for l in f if l.strip()]
            except Exception as e:
                pr(f"[-] Error: {e}", Cl.R)
                input(f"\n  {col('[Enter] back', Cl.D)}")
                return
        else:
            ips = ["104.16.45.78", "172.64.12.34", "162.158.88.22"]
        if not ips: pr("[-] Empty list", Cl.R); return
        proto = input(f"  {col('>', Cl.G)} Protocol (vless/vmess/reality) [vless]: ") or "vless"
        sni = input(f"  {col('>', Cl.G)} SNI [www.google.com]: ") or "www.google.com"
        try: cnt = int(input(f"  {col('>', Cl.G)} Config count [10]: ") or "10")
        except: cnt = 10
        mix = input(f"  {col('>', Cl.G)} Mix method (random/interleave/block) [random]: ") or "random"
        cfgs, links = self.cg.batch(ips, proto, sni, cnt, mix)
        rp = self.rp.html_report([], cfgs, proto, sni)
        self.rp.save_txt(links, f"links_{proto}.txt")
        self.rp.save_json(cfgs, f"configs_{proto}.json")
        pr(f"\n  {col('OK', Cl.G)} {cnt} configs generated")
        pr(f"  {col('OK', Cl.G)} Report: {rp}")
        print(f"\n  {col('Sample links:', Cl.BD)}")
        for i, l in enumerate(links[:5], 1):
            d = l[:90]+"..." if len(l)>90 else l
            print(f"    {i}. {col(d, Cl.D)}")
        input(f"\n  {col('[Enter] back', Cl.D)}")
    
    def m_mixed(self):
        print(); pr("-"*45, Cl.D)
        pr("[*] Mixed Mode (All-in-One)", Cl.BD+Cl.M)
        pr("    Full scan + DNS + SNI + Config", Cl.D)
        pr("-"*45, Cl.D)
        d = input(f"\n  {col('>', Cl.G)} Domain: ")
        dns_res = self.dns.propagation(d)
        dns_ips = []
        for s, data in dns_res.items():
            if data['status']=="ok": dns_ips.extend(data['ips'])
        pr(f"\n  {col('OK', Cl.G)} DNS: {len(dns_ips)} IPs")
        pr(f"\n  Scanning clean IPs from CDN...", Cl.Y)
        ips = self.cs.gen_ips("all", 300)
        clean = self.cs.scan(ips, d)
        if not clean and not dns_ips:
            pr("[-] No IPs found!", Cl.R)
            input(f"\n  {col('[Enter] back', Cl.D)}")
            return
        all_ips = list(set([x['ip'] for x in clean]+dns_ips))
        pr(f"\n  Checking SNI...", Cl.Y)
        if clean:
            best_ip = clean[0]['ip']
            sni_res = SSLModule.check_sni(best_ip, self.cfg.sni_list)
            working = [s for s, r in sni_res.items() if r and not r.get("error")]
            best_sni = working[0] if working else d
        else: best_sni = d
        pr(f"\n  Generating configs...", Cl.Y)
        cfgs, links = self.cg.batch(all_ips, "vless", best_sni, 10)
        rp = self.rp.html_report(clean, cfgs, "vless", best_sni)
        self.rp.save_json({"dns":dns_res, "clean_ips":clean[:20], "configs":cfgs}, "mixed_full.json")
        print(); pr("-"*45, Cl.G)
        pr("FINAL RESULTS:", Cl.BD+Cl.G)
        print(f"  {col('DNS IPs:', Cl.C)} {len(dns_ips)}")
        print(f"  {col('Clean IPs:', Cl.C)} {len(clean)}")
        print(f"  {col('SNI:', Cl.C)} {best_sni}")
        print(f"  {col('Configs:', Cl.C)} {len(cfgs)}")
        print(f"  {col('Report:', Cl.C)} {rp}")
        pr("-"*45, Cl.G)
        print(f"\n{col('Top 5 IPs:', Cl.BD)}")
        for i, d in enumerate(clean[:5], 1):
            print(f"  {i}. {col(d['ip'], Cl.C)} - {d['tcp']['best_latency']:.0f}ms - {d['score']:.1f}")
        print(f"\n{col('First 3 links:', Cl.BD)}")
        for i, l in enumerate(links[:3], 1):
            d = l[:100]+"..." if len(l)>100 else l
            print(f"  {i}. {col(d, Cl.D)}")
        input(f"\n  {col('[Enter] back', Cl.D)}")
    
    def run(self):
        self.banner()
        if not DNS_OK:
            pr("[!] dnspython not installed. Using fallback resolver.", Cl.Y)
            pr("    Install: pip install dnspython", Cl.Y)
        self.menu()

if __name__ == "__main__":
    app = App()
    try:
        app.run()
    except KeyboardInterrupt:
        print(); pr("[-] Stopped.", Cl.Y)
    except Exception as e:
        print(); pr(f"[!] Error: {e}", Cl.R)
        import traceback; traceback.print_exc()
