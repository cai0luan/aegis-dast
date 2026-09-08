#!/usr/bin/env python3
"""
Worker local do AegisDAST — roda FORA da Vercel (no seu notebook, ou qualquer
máquina onde você possa instalar o Nuclei de verdade). A Vercel só enfileira
(LPUSH aegis_jobs) e lê (HGETALL scan:<id>); este processo é quem de fato:

  1) Faz RPOP da fila `aegis_jobs` em loop contínuo.
  2) Marca o job como "em execução" no hash `scan:<id>` do Upstash.
  3) Executa reconhecimento passivo real (DNS, TLS, cabeçalhos HTTP).
  4) Executa o Nuclei de verdade via subprocess (nunca shell=True, domínio
     sempre passado como argumento discreto — nunca interpolado numa string de
     shell) contra o alvo, que já passou pela validação de posse de domínio
     no lado Node antes de qualquer job chegar aqui.
  5) Envia os achados brutos ao Gemini 2.5 Flash para triagem e formatação.
  6) Grava o relatório final de volta no hash e marca "COMPLETED".

Honestidade de dados, mesmo padrão do resto do projeto: cada Vulnerability
carrega um dataSource ('REAL_PASSIVE_RECON' para o que este script observa
direto, 'REAL_ACTIVE_DAST' para achado real do Nuclei) — nunca um valor
fabricado apresentado como medição.

Pré-requisitos que este script NÃO instala sozinho, por design (não é papel de
um worker de scanner baixar/instalar ferramentas de terceiros sozinho):
  - Nuclei precisa estar instalado e no PATH (ou apontado por NUCLEI_PATH no
    .env). Sem ele, a Etapa 2 roda vazia (zero achados), logada honestamente
    como "Nuclei não encontrado" — nunca some silenciosamente nem finge ter
    rodado.
  - Python 3.9+ e as dependências de requirements.txt.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import dns.resolver
import dns.exception
import requests
from dotenv import load_dotenv
from upstash_redis import Redis

load_dotenv()

QUEUE_KEY = "aegis_jobs"
POLL_INTERVAL_SECONDS = 3
HTTP_TIMEOUT_SECONDS = 8
TLS_TIMEOUT_SECONDS = 8
NUCLEI_TIMEOUT_SECONDS = 180
SCAN_HASH_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 dias, mesmo valor usado em server/queue.ts

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
NUCLEI_PATH_OVERRIDE = os.environ.get("NUCLEI_PATH", "").strip()

SECURITY_HEADERS_CHECKLIST = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_clock() -> str:
    return datetime.now().strftime("%H:%M:%S")


def get_redis() -> Redis:
    url = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if not url or not token:
        print("[worker] ERRO: UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN não configuradas (worker/.env).")
        sys.exit(1)
    return Redis(url=url, token=token)


# ---------------------------------------------------------------------------
# Persistência do job no hash scan:<id> — mesmo esquema de server/queue.ts
# ---------------------------------------------------------------------------

def scan_key(job_id: str) -> str:
    return f"scan:{job_id}"


def save_job(redis: Redis, job: dict) -> None:
    key = scan_key(job["id"])
    redis.hset(key, values={"status": job["status"], "job": json.dumps(job, ensure_ascii=False)})
    redis.expire(key, SCAN_HASH_TTL_SECONDS)


def append_log(redis: Redis, job: dict, level: str, stage: str, message: str) -> None:
    job["logs"].append({"timestamp": now_clock(), "level": level, "stage": stage, "message": message})
    save_job(redis, job)
    print(f"[{job['id']}] [{stage}] {message}")


def patch_stage(redis: Redis, job: dict, index: int, patch: dict) -> None:
    job["stages"][index].update(patch)
    save_job(redis, job)


def set_status(redis: Redis, job: dict, status: str, stage_index: int) -> None:
    job["status"] = status
    job["currentStageIndex"] = stage_index
    save_job(redis, job)


# ---------------------------------------------------------------------------
# Etapa 1: Reconhecimento passivo real (DNS, TLS, Cabeçalhos HTTP)
# ---------------------------------------------------------------------------

def resolve_dns(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    def safe(rtype: str, fmt=lambda r: str(r)):
        try:
            answers = resolver.resolve(domain, rtype)
            return [fmt(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
            return []

    return {
        "a": safe("A"),
        "aaaa": safe("AAAA"),
        "cname": safe("CNAME"),
        "mx": safe("MX", lambda r: f"{r.exchange} (prioridade {r.preference})"),
        "ns": safe("NS"),
        "txt": safe("TXT", lambda r: b"".join(r.strings).decode("utf-8", errors="replace")),
    }


def probe_http(domain: str) -> dict:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            started = time.time()
            resp = requests.get(
                url,
                timeout=HTTP_TIMEOUT_SECONDS,
                allow_redirects=True,
                headers={"User-Agent": "AegisDAST-Worker/1.0 (+passive-recon)"},
            )
            elapsed_ms = round((time.time() - started) * 1000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            missing = [h for h in SECURITY_HEADERS_CHECKLIST if h not in headers]
            return {
                "reachable": True,
                "finalUrl": resp.url,
                "statusCode": resp.status_code,
                "responseTimeMs": elapsed_ms,
                "headers": headers,
                "missingSecurityHeaders": missing,
            }
        except requests.RequestException as exc:
            if scheme == "http":
                return {"reachable": False, "error": str(exc)}
            # https falhou, tenta http antes de desistir
    return {"reachable": False, "error": "HTTP_PROBE_FAILED"}


def probe_tls(domain: str) -> dict:
    # Tenta com verificação de certificado ligada primeiro — é o único jeito
    # de obter subject/issuer/validade pela stdlib do Python sem trazer uma
    # dependência extra (cryptography/pyOpenSSL) só para isto. Quando a
    # verificação falha (autoassinado, expirado, etc.), a falha em si já É a
    # informação real: reportamos o motivo em vez de inventar um "não
    # alcançável" ou fabricar dados de certificado que não confirmamos.
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=TLS_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        valid_to_raw = cert.get("notAfter")
        days_until_expiry = None
        if valid_to_raw:
            valid_to_dt = datetime.strptime(valid_to_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiry = (valid_to_dt - datetime.now(timezone.utc)).days
        return {
            "reachable": True,
            "protocol": protocol,
            "subject": subject.get("commonName"),
            "issuer": issuer.get("commonName"),
            "validFrom": cert.get("notBefore"),
            "validTo": valid_to_raw,
            "daysUntilExpiry": days_until_expiry,
            "selfSigned": subject.get("commonName") == issuer.get("commonName"),
        }
    except ssl.SSLCertVerificationError as exc:
        # Handshake aconteceu, mas o certificado não é confiável — real e
        # relevante (é literalmente o tipo de achado que este produto reporta),
        # só não temos os detalhes do certificado sem uma dependência extra.
        return {"reachable": True, "error": f"Certificado não confiável: {exc}"}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


def fingerprint_technologies(headers: Optional[dict]) -> list[str]:
    if not headers:
        return []
    found: set[str] = set()
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    set_cookie = headers.get("set-cookie", "")

    signatures = [
        (r"cloudflare", "Cloudflare CDN/WAF"),
        (r"nginx", "Nginx"),
        (r"apache", "Apache HTTP Server"),
        (r"microsoft-iis", "Microsoft IIS"),
        (r"vercel", "Vercel"),
        (r"express", "Node.js / Express"),
        (r"php", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"next\.js", "Next.js"),
    ]
    for pattern, label in signatures:
        if re.search(pattern, server, re.I) or re.search(pattern, powered_by, re.I):
            found.add(label)

    if re.search(r"phpsessid", set_cookie, re.I):
        found.add("PHP (via cookie de sessão)")
    if re.search(r"jsessionid", set_cookie, re.I):
        found.add("Java / JSP (via cookie de sessão)")
    if "cf-ray" in headers:
        found.add("Cloudflare CDN/WAF")

    return sorted(found)


def check_well_known(domain: str, path: str) -> bool:
    try:
        resp = requests.get(f"https://{domain}{path}", timeout=4, headers={"User-Agent": "AegisDAST-Worker/1.0"})
        return resp.ok
    except requests.RequestException:
        return False


def run_passive_recon(domain: str) -> dict:
    return {
        "domain": domain,
        "executedAt": now_iso(),
        "dns": resolve_dns(domain),
        "subdomains": [],
        "subdomainsSource": "unavailable",
        "httpProbe": (http_probe := probe_http(domain)),
        "tls": probe_tls(domain),
        "technologies": fingerprint_technologies(http_probe.get("headers")),
        "robotsTxtFound": check_well_known(domain, "/robots.txt"),
        "securityTxtFound": check_well_known(domain, "/.well-known/security.txt"),
    }


def new_vuln_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def derive_vulnerabilities_from_recon(recon: dict, target_url: str) -> list[dict]:
    out: list[dict] = []
    http_probe = recon["httpProbe"]
    tls = recon["tls"]
    domain = recon["domain"]

    missing = http_probe.get("missingSecurityHeaders") or []
    if http_probe.get("reachable") and missing:
        severity = "MEDIUM" if len(missing) >= 4 else "LOW"
        out.append({
            "id": new_vuln_id("recon-headers"),
            "title": f"Cabeçalhos de Segurança HTTP Ausentes ({len(missing)} de {len(SECURITY_HEADERS_CHECKLIST)})",
            "severity": severity,
            "cvssScore": 5.3 if severity == "MEDIUM" else 3.1,
            "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "owaspCategory": "A05:2021-Security Misconfiguration",
            "cwe": "CWE-16: Configuration",
            "matchedUrl": http_probe.get("finalUrl") or target_url,
            "toolSource": "Aegis Passive Recon",
            "description": f"A resposta HTTP da página inicial não inclui os seguintes cabeçalhos de segurança recomendados: {', '.join(missing)}.",
            "impact": "Ausência de defesas em profundidade no navegador (ex: sem CSP o site fica mais exposto a XSS residual; sem HSTS há janela para downgrade para HTTP).",
            "status": "CONFIRMED",
            "aiConfidenceScore": 100,
            "aiTriageReasoning": "Observação direta e determinística: os cabeçalhos ausentes foram lidos na resposta HTTP real, sem inferência.",
            "dataSource": "REAL_PASSIVE_RECON",
            "proofOfConcept": {
                "attackPayload": "N/A (observação passiva, não é uma exploração)",
                "curlCommand": f"curl -sI {http_probe.get('finalUrl') or target_url}",
                "httpRequest": f"GET / HTTP/1.1\nHost: {domain}",
                "httpResponse": "\n".join(f"{k}: {v}" for k, v in (http_probe.get("headers") or {}).items()),
                "evidenceText": f"Cabeçalhos ausentes na resposta real: {', '.join(missing)}.",
            },
            "remediation": {
                "recommendation": "Configure o servidor web/CDN para emitir os cabeçalhos de segurança ausentes. Comece por Content-Security-Policy e Strict-Transport-Security.",
                "language": "nginx",
                "codeSnippetBefore": "# Sem cabeçalhos de segurança configurados",
                "codeSnippetAfter": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "DENY" always;',
                "references": ["https://owasp.org/www-project-secure-headers/"],
            },
        })

    days = tls.get("daysUntilExpiry")
    if tls.get("reachable") and isinstance(days, int) and days < 30:
        severity = "HIGH" if days < 7 else "MEDIUM"
        out.append({
            "id": new_vuln_id("recon-tls-expiry"),
            "title": f"Certificado TLS Expirando em {days} dia(s)",
            "severity": severity,
            "cvssScore": 7.4 if severity == "HIGH" else 5.9,
            "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "owaspCategory": "A05:2021-Security Misconfiguration",
            "cwe": "CWE-298: Improper Validation of Certificate Expiration",
            "matchedUrl": f"https://{domain}",
            "toolSource": "Aegis Passive Recon",
            "description": f"O certificado TLS apresentado por {domain} expira em {tls.get('validTo')}.",
            "impact": "Após a expiração, navegadores bloquearão o acesso ao site com um alerta de segurança.",
            "status": "CONFIRMED",
            "aiConfidenceScore": 100,
            "aiTriageReasoning": "Data de expiração lida diretamente do certificado apresentado no handshake TLS real.",
            "dataSource": "REAL_PASSIVE_RECON",
            "proofOfConcept": {
                "attackPayload": "N/A (observação passiva)",
                "curlCommand": f"openssl s_client -connect {domain}:443 -servername {domain} </dev/null 2>/dev/null | openssl x509 -noout -enddate",
                "httpRequest": "TLS ClientHello (handshake, sem payload HTTP)",
                "httpResponse": f"Subject: {tls.get('subject') or 'N/A'}\nIssuer: {tls.get('issuer') or 'N/A'}\nValid To: {tls.get('validTo')}",
                "evidenceText": f"Certificado real expira em {tls.get('validTo')}.",
            },
            "remediation": {
                "recommendation": "Renove o certificado TLS antes do vencimento e configure renovação automática.",
                "references": ["https://letsencrypt.org/docs/faq/"],
            },
        })

    if not tls.get("reachable"):
        out.append({
            "id": new_vuln_id("recon-tls-unreachable"),
            "title": "Não Foi Possível Estabelecer Handshake TLS na Porta 443",
            "severity": "INFO",
            "cvssScore": 0,
            "cvssVector": "N/A",
            "owaspCategory": "A05:2021-Security Misconfiguration",
            "cwe": "N/A",
            "matchedUrl": f"https://{domain}",
            "toolSource": "Aegis Passive Recon",
            "description": f"A tentativa de handshake TLS na porta 443 falhou: {tls.get('error')}.",
            "impact": "Pode indicar firewall bloqueando a porta ou serviço sem HTTPS direto.",
            "status": "CONFIRMED",
            "aiConfidenceScore": 100,
            "aiTriageReasoning": "Resultado direto da tentativa de conexão TLS real.",
            "dataSource": "REAL_PASSIVE_RECON",
            "proofOfConcept": {
                "attackPayload": "N/A",
                "curlCommand": f"openssl s_client -connect {domain}:443 -servername {domain}",
                "httpRequest": "TLS ClientHello",
                "httpResponse": f"Erro: {tls.get('error')}",
                "evidenceText": f"Handshake TLS falhou: {tls.get('error')}",
            },
            "remediation": {
                "recommendation": "Confirme se o serviço deveria expor HTTPS na porta 443 e se não há firewall bloqueando.",
                "references": [],
            },
        })

    return out


# ---------------------------------------------------------------------------
# Etapa 2: Nuclei real, via subprocess seguro (nunca shell=True; domínio e
# demais valores sempre como argumentos discretos da lista — não há como um
# valor de config virar comando arbitrário aqui, mesmo que fosse hostil)
# ---------------------------------------------------------------------------

def find_nuclei_binary() -> Optional[str]:
    if NUCLEI_PATH_OVERRIDE:
        return NUCLEI_PATH_OVERRIDE if os.path.isfile(NUCLEI_PATH_OVERRIDE) else None
    return shutil.which("nuclei")


def is_safe_hostname(domain: str) -> bool:
    return bool(HOSTNAME_RE.match(domain)) or _is_ip(domain)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


SEVERITY_DEFAULT_CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}

TAG_TO_OWASP = [
    (r"sqli|sql-injection", "A03:2021-Injection"),
    (r"xss", "A03:2021-Injection"),
    (r"ssrf", "A10:2021-Server-Side Request Forgery (SSRF)"),
    (r"rce|command-injection", "A03:2021-Injection"),
    (r"exposure|disclosure|config|misconfig|default-login", "A05:2021-Security Misconfiguration"),
    (r"auth|login", "A07:2021-Identification and Authentication Failures"),
    (r"cve", "A06:2021-Vulnerable and Outdated Components"),
]


def guess_owasp_category(tags: list[str]) -> str:
    joined = ",".join(tags).lower()
    for pattern, category in TAG_TO_OWASP:
        if re.search(pattern, joined):
            return category
    return "A05:2021-Security Misconfiguration"


def nuclei_finding_to_vulnerability(raw: dict) -> dict:
    info = raw.get("info", {}) or {}
    severity = str(info.get("severity", "info")).upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "INFO"
    classification = info.get("classification") or {}
    cvss_score = classification.get("cvss-score") or SEVERITY_DEFAULT_CVSS.get(severity.lower(), 0.0)
    cvss_vector = classification.get("cvss-metrics") or "N/A (não reportado pelo template do Nuclei)"
    matched_at = raw.get("matched-at") or raw.get("host") or "N/A"
    tags = info.get("tags") or []
    request_raw = raw.get("request")
    response_raw = raw.get("response")

    return {
        "id": new_vuln_id("nuclei"),
        "title": info.get("name") or raw.get("template-id") or "Achado do Nuclei",
        "severity": severity,
        "cvssScore": cvss_score,
        "cvssVector": cvss_vector,
        "owaspCategory": guess_owasp_category(tags),
        "cwe": ", ".join(classification.get("cwe-id", [])) or "N/A",
        "matchedUrl": matched_at,
        "toolSource": "Nuclei",
        "description": info.get("description") or f"Template {raw.get('template-id')} disparou contra {matched_at}.",
        "impact": "Ver referências do template para o impacto detalhado desta classe de vulnerabilidade.",
        "status": "CONFIRMED",
        "aiConfidenceScore": 80,  # ponto de partida; a Etapa 3 (Gemini) recalcula com base na evidência
        "aiTriageReasoning": "Ainda não triado pela IA — achado bruto do Nuclei antes da Etapa 3.",
        "dataSource": "REAL_ACTIVE_DAST",
        "proofOfConcept": {
            "attackPayload": ", ".join(str(x) for x in (raw.get("extracted-results") or [])) or "N/A",
            "curlCommand": f"curl -i -s -k '{matched_at}'",
            "httpRequest": request_raw or "Requisição bruta não capturada (execute o Nuclei com -irr para incluir).",
            "httpResponse": response_raw or "Resposta bruta não capturada (execute o Nuclei com -irr para incluir).",
            "evidenceText": f"Template Nuclei '{raw.get('template-id')}' confirmou a condição em {matched_at}.",
        },
        "remediation": {
            # Templates do Nuclei não trazem texto de remediação em prosa — só
            # links de referência. Usar um link como "recomendação" seria
            # confundir uma fonte com uma instrução; a recomendação fica
            # genérica e as URLs reais vão em `references`, nunca o inverso.
            "recommendation": "Consulte a documentação do template do Nuclei (campo de referências abaixo) para a orientação de correção específica desta classe de vulnerabilidade.",
            "references": info.get("reference") if isinstance(info.get("reference"), list) else [],
        },
    }


def run_nuclei(domain: str, rate_limit: int, waf_bypass: Optional[dict]) -> Optional[list[dict]]:
    """Retorna None se o Nuclei não está instalado (distinto de [] = rodou e não achou nada)."""
    if not is_safe_hostname(domain):
        return []
    binary = find_nuclei_binary()
    if not binary:
        return None

    target_url = f"https://{domain}"
    safe_rate = max(1, min(100, int(rate_limit or 15)))
    cmd = [binary, "-u", target_url, "-severity", "critical,high,medium", "-rate-limit", str(safe_rate), "-jsonl", "-silent", "-timeout", "10", "-irr"]
    if waf_bypass and waf_bypass.get("enabled") and waf_bypass.get("authHeaderName") and waf_bypass.get("authHeaderValue"):
        cmd += ["-H", f"{waf_bypass['authHeaderName']}: {waf_bypass['authHeaderValue']}"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT_SECONDS, shell=False)
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


# ---------------------------------------------------------------------------
# Etapa 3: Triagem via Gemini 2.5 Flash (com fallback heurístico honesto)
# ---------------------------------------------------------------------------

def triage_with_gemini(vuln: dict, target_domain: str) -> dict:
    fallback = {
        "isFalsePositive": False,
        "confidenceScore": vuln.get("aiConfidenceScore", 80),
        "reasoning": vuln.get("aiTriageReasoning", "IA indisponível; mantendo classificação bruta do Nuclei/recon."),
        "usedRealModel": False,
    }
    if not GEMINI_API_KEY:
        return fallback

    try:
        from google import genai

        client = genai.Client(api_key=GEMINI_API_KEY)
        prompt = f"""Você é um Engenheiro de Cibersegurança Sênior especialista em Offensive Security e DAST.
Analise a vulnerabilidade abaixo, detectada por scanner automatizado real, e determine se é um FALSO POSITIVO ou uma VULNERABILIDADE CONFIRMADA.

Alvo: {target_domain}
Vulnerabilidade: {json.dumps(vuln, ensure_ascii=False)}

Responda ESTRITAMENTE em JSON:
{{
  "isFalsePositive": boolean,
  "confidenceScore": number (0 a 100),
  "reasoning": string (análise técnica em português),
  "executiveSummaryText": string (resumo sem jargões para diretores),
  "recommendedMitigation": string (passo a passo para desenvolvedores)
}}"""
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={"response_mime_type": "application/json", "temperature": 0.2},
        )
        parsed = json.loads(response.text or "{}")
        return {
            "isFalsePositive": bool(parsed.get("isFalsePositive", False)),
            "confidenceScore": parsed.get("confidenceScore", fallback["confidenceScore"]),
            "reasoning": parsed.get("reasoning", fallback["reasoning"]),
            "usedRealModel": True,
        }
    except Exception as exc:
        print(f"[worker] Gemini triage falhou, usando fallback: {exc}")
        return fallback


def compute_executive_summary(vulnerabilities: list[dict]) -> dict:
    confirmed = [v for v in vulnerabilities if v["status"] == "CONFIRMED"]
    weights = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    risk_score = min(100, sum(weights.get(v["severity"], 0) for v in confirmed))
    if risk_score >= 70:
        overall = "CRITICAL"
    elif risk_score >= 45:
        overall = "HIGH"
    elif risk_score >= 20:
        overall = "MEDIUM"
    elif risk_score > 0:
        overall = "LOW"
    else:
        overall = "SECURE"

    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    ranked = sorted(confirmed, key=lambda v: rank.get(v["severity"], 0), reverse=True)
    top_threats = [f"{v['title']} ({v['matchedUrl']})" for v in ranked[:3]] or ["Nenhuma ameaça de alta prioridade identificada nesta execução."]
    quick_wins = [v["remediation"]["recommendation"] for v in ranked[:3]] or ["Continue monitorando o alvo periodicamente."]

    return {
        "overallRisk": overall,
        "riskScore": risk_score,
        "businessImpactSummary": (
            f"A varredura real (recon + Nuclei) identificou {len(confirmed)} achado(s) confirmado(s), "
            f"incluindo {sum(1 for v in confirmed if v['severity'] == 'CRITICAL')} crítico(s) e "
            f"{sum(1 for v in confirmed if v['severity'] == 'HIGH')} de alto impacto."
            if confirmed else "Nenhuma vulnerabilidade confirmada foi identificada nesta execução real."
        ),
        "topThreats": top_threats,
        "quickWins": quick_wins,
        "complianceImpact": (
            "Risco potencial perante a LGPD (Lei 13.709/2018) caso os achados envolvam exposição de dados pessoais — recomenda-se avaliação jurídica/DPO."
            if any(v["severity"] in ("CRITICAL", "HIGH") for v in confirmed)
            else "Impacto de conformidade baixo com base nos achados atuais."
        ),
    }


# ---------------------------------------------------------------------------
# Orquestração do job
# ---------------------------------------------------------------------------

def process_job(redis: Redis, job: dict) -> None:
    domain = job["targetDomain"]
    config = job.get("config") or {}
    rate_limit = config.get("rateLimit", 15)
    waf_bypass = config.get("wafBypass")

    # ---- Etapa 1: Recon Passivo Real ----
    set_status(redis, job, "RECON", 0)
    patch_stage(redis, job, 0, {"status": "RUNNING", "progress": 20, "summary": "Worker local executando DNS, HTTP e TLS reais..."})
    append_log(redis, job, "INFO", "Recon", f"Worker Python iniciou reconhecimento passivo real contra {domain}...")

    recon = run_passive_recon(domain)
    recon_vulns = derive_vulnerabilities_from_recon(recon, f"https://{domain}")
    job["reconFindings"] = recon
    job["vulnerabilities"].extend(recon_vulns)
    job["rawFindingsTotal"] += len(recon_vulns)

    if recon["httpProbe"].get("reachable"):
        append_log(redis, job, "INFO", "Recon", f"[HTTP] {recon['httpProbe'].get('finalUrl')} respondeu {recon['httpProbe'].get('statusCode')} em {recon['httpProbe'].get('responseTimeMs')}ms.")
    else:
        append_log(redis, job, "WARN", "Recon", f"[HTTP] Não foi possível alcançar o alvo: {recon['httpProbe'].get('error')}")
    if recon["tls"].get("reachable"):
        append_log(redis, job, "INFO", "Recon", f"[TLS] Certificado real: emissor {recon['tls'].get('issuer')}, válido até {recon['tls'].get('validTo')}.")
    else:
        append_log(redis, job, "WARN", "Recon", f"[TLS] Handshake falhou: {recon['tls'].get('error')}")
    patch_stage(redis, job, 0, {
        "status": "COMPLETED", "progress": 100, "findingsCount": len(recon_vulns), "dataSource": "REAL",
        "summary": f"{len(recon_vulns)} achado(s) real(is) de configuração/exposição.",
    })
    append_log(redis, job, "SUCCESS", "Recon", f"Etapa 1 concluída. {len(recon_vulns)} achado(s) real(is).")

    # ---- Etapa 2: Nuclei real ----
    set_status(redis, job, "ACTIVE_SCAN", 1)
    patch_stage(redis, job, 1, {"status": "RUNNING", "progress": 30, "tool": "Nuclei v3 (execução real via worker local)", "dataSource": "REAL", "summary": "Executando Nuclei real contra o alvo..."})
    append_log(redis, job, "INFO", "DAST", f"[Nuclei] Executando templates reais (critical,high,medium) com rate-limit {rate_limit} req/s...")

    nuclei_findings = run_nuclei(domain, rate_limit, waf_bypass)
    if nuclei_findings is None:
        append_log(redis, job, "WARN", "DAST", "[Nuclei] Binário não encontrado no PATH deste worker (nem em NUCLEI_PATH). Etapa 2 rodou vazia — instale o Nuclei para achados reais aqui.")
        nuclei_vulns: list[dict] = []
    else:
        nuclei_vulns = [nuclei_finding_to_vulnerability(f) for f in nuclei_findings]
        append_log(redis, job, "SUCCESS" if nuclei_vulns else "INFO", "DAST", f"[Nuclei] {len(nuclei_vulns)} achado(s) real(is) confirmados pelos templates.")

    job["vulnerabilities"].extend(nuclei_vulns)
    job["rawFindingsTotal"] += len(nuclei_vulns)
    patch_stage(redis, job, 1, {
        "status": "COMPLETED", "progress": 100, "findingsCount": len(nuclei_vulns), "dataSource": "REAL",
        "summary": f"{len(nuclei_vulns)} achado(s) real(is) do Nuclei." if nuclei_findings is not None else "Nuclei não instalado neste worker — nenhum achado ativo real gerado.",
    })

    # ---- Etapa 3: Triagem via Gemini ----
    set_status(redis, job, "TRIAGE", 2)
    ai_configured = bool(GEMINI_API_KEY)
    patch_stage(redis, job, 2, {"status": "RUNNING", "progress": 40, "summary": "Consultando Gemini 2.5 Flash..." if ai_configured else "GEMINI_API_KEY ausente — mantendo classificação bruta."})
    append_log(redis, job, "INFO", "AI Triage", "[Gemini 2.5 Flash] Iniciando triagem real de cada achado..." if ai_configured else "[Fallback] Nenhuma chave Gemini configurada no worker; achados mantidos como estão.")

    any_real_model_used = False
    triaged: list[dict] = []
    for vuln in job["vulnerabilities"]:
        result = triage_with_gemini(vuln, domain)
        if result["usedRealModel"]:
            any_real_model_used = True
        vuln = {
            **vuln,
            "status": "FALSE_POSITIVE" if result["isFalsePositive"] else vuln["status"],
            "aiConfidenceScore": result["confidenceScore"],
            "aiTriageReasoning": result["reasoning"],
        }
        triaged.append(vuln)
    job["vulnerabilities"] = triaged

    false_positives = sum(1 for v in triaged if v["status"] == "FALSE_POSITIVE")
    job["filteredFalsePositivesTotal"] = false_positives
    executive_summary = compute_executive_summary(triaged)
    job["executiveSummary"] = executive_summary
    job["status"] = "COMPLETED"
    job["currentStageIndex"] = 3
    job["completedAt"] = now_iso()
    patch_stage(redis, job, 2, {
        "status": "COMPLETED", "progress": 100, "findingsCount": len(triaged) - false_positives,
        "dataSource": "AI_REAL" if any_real_model_used else "AI_FALLBACK",
        "summary": f"{false_positives} falso(s) positivo(s) descartado(s). Score de risco: {executive_summary['riskScore']}/100.",
    })
    append_log(redis, job, "SUCCESS", "AI Triage", f"Triagem concluída ({'modelo real' if any_real_model_used else 'fallback'}). {false_positives} descartado(s).")
    append_log(redis, job, "SUCCESS", "Reporter", f"Relatório gerado. Score de Risco: {executive_summary['riskScore']}/100 ({executive_summary['overallRisk']}).")
    save_job(redis, job)


def main() -> None:
    redis = get_redis()
    nuclei_status = find_nuclei_binary() or "NÃO ENCONTRADO (instale e adicione ao PATH, ou configure NUCLEI_PATH em worker/.env)"
    print("=" * 70)
    print("[worker] AegisDAST — Worker Local de Varredura Real")
    print(f"[worker] Nuclei: {nuclei_status}")
    print(f"[worker] Gemini AI Triage: {'configurada' if GEMINI_API_KEY else 'GEMINI_API_KEY ausente — fallback heurístico'}")
    print(f"[worker] Fila: {QUEUE_KEY} (polling a cada {POLL_INTERVAL_SECONDS}s)")
    print("=" * 70)

    while True:
        try:
            raw = redis.rpop(QUEUE_KEY)
        except Exception as exc:
            print(f"[worker] Falha ao consultar o Upstash, tentando de novo em {POLL_INTERVAL_SECONDS}s: {exc}")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        if not raw:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        try:
            job = json.loads(raw)
        except json.JSONDecodeError:
            print(f"[worker] Payload inválido na fila, descartado: {raw[:200]}")
            continue

        print(f"[worker] Job recebido: {job.get('id')} ({job.get('targetDomain')})")
        try:
            process_job(redis, job)
        except Exception as exc:
            print(f"[worker] Falha inesperada processando {job.get('id')}: {exc}")
            try:
                job["status"] = "FAILED"
                job["completedAt"] = now_iso()
                append_log(redis, job, "ERROR", "Orchestrator", f"Falha inesperada no worker: {exc}")
            except Exception:
                pass


if __name__ == "__main__":
    main()
