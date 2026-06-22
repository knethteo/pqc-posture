import os
import re
import time
import json
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, Any, Set, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv

warnings.filterwarnings("ignore", category=DeprecationWarning)
load_dotenv()

app = FastAPI(title="PQC Posture")

# ─── Plugin Configuration ────────────────────────────────────────────────────
# Edit this dict to add / remove plugin IDs from the PQC signal set.
PLUGINS: Dict[str, Dict[int, str]] = {
    "core_pqc": {
        277650: "Remote Services Not Using Post-Quantum Ciphers",
        277651: "Post-quantum X509 Signature Algorithms",
        277652: "Target Cipher Inventory",
        277653: "Remote Services Using Post-Quantum Ciphers",
        277654: "TLS Supported Groups",
        298387: "Shor's Harvest Now Decrypt Later",
    },
    "cipher_inventory": {
        21643:  "SSL Cipher Suites Supported",
        70657:  "SSH Algorithms and Languages Supported",
        57041:  "SSL Perfect Forward Secrecy Cipher Suites Supported",
        156899: "SSL/TLS Recommended Cipher Suites",
        70544:  "SSL Cipher Block Chaining Cipher Suites Supported",
        42873:  "SSL Medium Strength Cipher Suites Supported (SWEET32)",
    },
    "weak_key_exchange": {
        83875:  "SSH Weak Key Exchange Algorithms Enabled",
        53360:  "SSL/TLS Diffie-Hellman Modulus ≤ 1024 Bits (Logjam)",
        106459: "SSH Weak Algorithms Supported",
        81606:  "SSL/TLS EXPORT_RSA ≤ 512-bit Cipher Suites (FREAK)",
        83738:  "SSL/TLS Diffie-Hellman Modulus ≤ 2048 Bits",
    },
    "ssh_hygiene": {
        153953: "SSH Server CBC Mode Ciphers Enabled",
        90317:  "SSH Weak MAC Algorithms Enabled",
        153954: "SSH Server HMAC Weak Algorithms",
        187315: "SSH Deprecated Algorithms Supported",
        153588: "SSH SHA-1 HMAC Algorithms Enabled",
    },
    "cert_crypto_agility": {
        35291:  "SSL Certificate Signed Using Weak Hashing Algorithm",
        86067:  "SSL Certificate Chain Contains Weak Hash Algorithms",
        60108:  "SSL Certificate Chain Contains RSA Keys < 2048 bits",
        103864: "SSL Certificate with Wrong Hostname",
        45411:  "SSL Certificate with Wrong Hostname",
        51192:  "SSL Certificate Cannot Be Trusted",
        15901:  "SSL Certificate Expiry",
        10863:  "SSL Certificate Information",
        42981:  "SSL Certificate Expiry - Future Expiry",
        83298:  "SSL Certificate Chain Contains Certificates Expiring Soon",
        45410:  "SSL Certificate 'commonName' Mismatch",
        159544: "SSL Certificate with no Common Name",
    },
    "legacy_protocols": {
        20007:  "SSL Version 2 and 3 Protocol Detection",
        104743: "TLS Version 1.0 Protocol Detection",
        157288: "TLS Version 1.1 Protocol Deprecated",
        121010: "TLS Version 1.1 Protocol Detection",
        136318: "TLS Version 1.2 Protocol Detection",
        138330: "TLS Version 1.3 Protocol Detection",  # good signal
    },
    "windows_ad": {
        150481: "Kerberos Weak Encryption Type",
    },
    "was_ssl_tls": {
        112530: "SSL/TLS Versions Supported",
        112598: "SSL/TLS Server Cipher Suite Preference",
        115491: "SSL/TLS Cipher Suites Supported",
        112491: "SSL/TLS Certificate Information",
        113045: "SSL/TLS Certificate Contains Wildcard Entries",
    },
}

ALL_PLUGIN_IDS: Set[int] = {pid for group in PLUGINS.values() for pid in group}
PLUGIN_NAMES: Dict[int, str] = {pid: name for group in PLUGINS.values() for pid, name in group.items()}
PLUGIN_CATEGORY: Dict[int, str] = {
    pid: cat for cat, group in PLUGINS.items() for pid in group
}

PQC_NOT_SAFE: Set[int] = {277650, 298387}
PQC_SAFE: Set[int] = {277653}
PQC_CORE: Set[int] = set(PLUGINS["core_pqc"].keys())

SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

PORT_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP/TLS", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM", 5986: "WinRM-HTTPS",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9443: "HTTPS-Alt",
}


def _parse_shors_output(raw_text: str) -> List[dict]:
    """Parse plugin 298387 output into [{service, port, tls_version, display, ciphers}].

    Handles the real Tenable output format:
      The TLS service on port 443/TLSv1.2 offers these ciphers vulnerable to Shor's:
              TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    Also handles older compact format:
      Port 443/tcp :
        TLSv1.2
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    """
    services: List[dict] = []
    current: Optional[dict] = None

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Real format: "The TLS service on port 443/TLSv1.2 offers these ciphers..."
        real_match = re.match(
            r"the tls service on port (\d+)/(TLSv?[\d.]+)",
            stripped, re.IGNORECASE
        )
        if real_match:
            port_num = int(real_match.group(1))
            tls_ver  = real_match.group(2)
            service_name = PORT_SERVICES.get(port_num, f"Port {port_num}")
            current = {
                "service": service_name,
                "port": port_num,
                "tls_version": tls_ver,
                "display": f"{service_name} — port {port_num} / {tls_ver}",
                "ciphers": [],
            }
            services.append(current)
            continue

        # Compact format: "Port 443/tcp :" or "443/tcp :"
        port_match = re.match(r"(?:Port\s+)?(\d+)/(tcp|udp)", stripped, re.IGNORECASE)
        if port_match:
            port_num = int(port_match.group(1))
            service_name = PORT_SERVICES.get(port_num, f"Port {port_num}")
            tls_inline = re.search(r"TLSv?\s*([\d.]+)", stripped, re.IGNORECASE)
            tls_ver = f"TLSv{tls_inline.group(1)}" if tls_inline else None
            current = {
                "service": service_name,
                "port": port_num,
                "tls_version": tls_ver,
                "display": f"{service_name} — port {port_num}" + (f" / {tls_ver}" if tls_ver else ""),
                "ciphers": [],
            }
            services.append(current)
            continue

        # Standalone TLS version line (compact format follow-up)
        tls_match = re.match(r"TLSv?\s*([\d.]+)", stripped, re.IGNORECASE)
        if tls_match and current is not None and not current["tls_version"]:
            current["tls_version"] = f"TLSv{tls_match.group(1)}"
            current["display"] = current["display"].rstrip() + f" / TLSv{tls_match.group(1)}"
            continue

        # Cipher name: TLS_* or SSL_*
        cipher_match = re.match(r"((?:TLS|SSL)_[A-Z0-9_]+)", stripped)
        if cipher_match:
            cipher = cipher_match.group(1)
            if current is None:
                current = {
                    "service": "Unknown service",
                    "port": None,
                    "tls_version": None,
                    "display": "Unknown service",
                    "ciphers": [],
                }
                services.append(current)
            current["ciphers"].append(cipher)

    return services

# ─── Key Management ──────────────────────────────────────────────────────────
_runtime_keys: Dict[str, str] = {}
KEYS_FILE = ".tio_keys"


def _load_stored_keys() -> None:
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE) as f:
                _runtime_keys.update(json.load(f))
        except Exception:
            pass


def _get_keys():
    access = os.getenv("TIO_ACCESS_KEY") or _runtime_keys.get("access_key")
    secret = os.getenv("TIO_SECRET_KEY") or _runtime_keys.get("secret_key")
    return access, secret


def _get_tio():
    from tenable.io import TenableIO
    access, secret = _get_keys()
    if not access or not secret:
        raise HTTPException(
            status_code=401,
            detail="Tenable API keys not configured. Visit /setup to add them.",
        )
    return TenableIO(access, secret)


_load_stored_keys()

# ─── Cache ───────────────────────────────────────────────────────────────────
_cache: Dict[str, Any] = {}
CACHE_TTL = 600  # 10 minutes


def _cache_get(key: str):
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return data
        del _cache[key]
    return None


def _cache_set(key: str, data: Any) -> None:
    _cache[key] = (data, time.time())


# ─── Verdict Logic ───────────────────────────────────────────────────────────
def compute_verdict(plugin_ids_present: Set[int], has_non_pqc_findings: bool = False) -> dict:
    has_not_safe = bool(plugin_ids_present & PQC_NOT_SAFE)
    has_safe = bool(plugin_ids_present & PQC_SAFE)
    has_any_core = bool(plugin_ids_present & PQC_CORE)

    if has_not_safe and not has_safe:
        return {"verdict": "Not Quantum-Safe", "verdict_color": "red"}
    if has_safe and not has_not_safe:
        return {"verdict": "Quantum-Safe", "verdict_color": "green"}
    # Has legacy/weak crypto findings but no PQC-specific scan data yet
    if not has_any_core and has_non_pqc_findings:
        return {"verdict": "Review", "verdict_color": "amber"}
    if not has_any_core:
        return {"verdict": "No PQC data", "verdict_color": "grey"}
    return {"verdict": "Review", "verdict_color": "amber"}


# ─── Asset field helpers ──────────────────────────────────────────────────────
# Both workbenches.assets() and asset_info() use these field names:
#   id, fqdn (list), hostname (list), netbios_name (list),
#   ipv4 (list), operating_system (list), last_seen

def _asset_name(asset: dict) -> str:
    for field in ("fqdn", "hostname", "netbios_name", "ipv4"):
        vals = asset.get(field) or []
        if vals:
            return vals[0]
    return asset.get("id", "Unknown")


def _first(lst, default=None):
    return lst[0] if lst else default


# ─── Auth endpoints ──────────────────────────────────────────────────────────
class KeysRequest(BaseModel):
    access_key: str
    secret_key: str


@app.get("/api/status")
def api_status():
    access, _ = _get_keys()
    return {"configured": bool(access)}


@app.post("/api/auth")
def set_keys(req: KeysRequest):
    from tenable.io import TenableIO
    try:
        tio = TenableIO(req.access_key, req.secret_key)
        # Lightweight validation: just iterate one asset
        for _ in tio.workbenches.assets():
            break
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Keys rejected by Tenable: {e}")

    _runtime_keys["access_key"] = req.access_key
    _runtime_keys["secret_key"] = req.secret_key

    try:
        with open(KEYS_FILE, "w") as f:
            json.dump({"access_key": req.access_key, "secret_key": req.secret_key}, f)
    except Exception:
        pass

    _cache.clear()
    return {"ok": True}


@app.get("/api/server-status")
def get_server_status():
    access, _ = _get_keys()
    if not access:
        return {"configured": False}
    try:
        tio = _get_tio()
        props = tio.server.properties()
        return {
            "configured": True,
            "container_id":   props.get("server_uuid"),
            "container_name": props.get("nessus_type"),
            "region":         props.get("region") or props.get("site_id"),
            "licence":        (props.get("license") or {}).get("type"),
            "access_key_hint": access[:8] + "****",
        }
    except Exception as e:
        return {"configured": True, "error": str(e), "access_key_hint": access[:8] + "****"}



@app.get("/api/pqc-assets")
def get_pqc_assets(
    search: Optional[str] = Query(default=None),
    sort: Optional[str] = Query(default=None),
):
    cache_key = "pqc_assets"
    cached = _cache_get(cache_key)

    if cached is None:
        tio = _get_tio()

        # Step 1: one batch query per plugin category (7 calls).
        # vuln_assets() accepts comma-separated plugin IDs → OR logic.
        # This gives us the asset universe + which categories fired per asset.
        asset_store: Dict[str, dict] = {}  # uuid -> {info, categories, pqc_plugins}
        NON_PQC_CATS = set(PLUGINS.keys()) - {"core_pqc"}

        for cat, group_plugins in PLUGINS.items():
            id_str = ",".join(str(p) for p in group_plugins.keys())
            try:
                for asset in tio.workbenches.vuln_assets(
                    ("plugin.id", "eq", id_str)
                ):
                    uid = asset.get("id")
                    if not uid:
                        continue
                    if uid not in asset_store:
                        asset_store[uid] = {
                            "info": asset,
                            "categories": set(),
                            "pqc_plugins": set(),
                        }
                    asset_store[uid]["categories"].add(cat)
            except Exception:
                pass

        # Step 2: individual queries for the 3 verdict-critical plugins.
        for pid in [277650, 298387, 277653]:
            try:
                for asset in tio.workbenches.vuln_assets(
                    ("plugin.id", "eq", str(pid))
                ):
                    uid = asset.get("id")
                    if uid in asset_store:
                        asset_store[uid]["pqc_plugins"].add(pid)
                    elif uid:
                        asset_store[uid] = {
                            "info": asset,
                            "categories": {"core_pqc"},
                            "pqc_plugins": {pid},
                        }
            except Exception:
                pass

        # Step 3: enrich with OS for all matched assets.
        os_lookup: Dict[str, Optional[str]] = {}
        for uid in asset_store:
            try:
                info = tio.workbenches.asset_info(uid)
                os_list = info.get("operating_system") or []
                os_lookup[uid] = _first(os_list)
            except Exception:
                os_lookup[uid] = None

        result = []
        for uid, data in asset_store.items():
            pqc_plugins = data["pqc_plugins"]
            categories = data["categories"]
            has_non_pqc = bool(categories & NON_PQC_CATS)
            asset = data["info"]
            result.append(
                {
                    "uuid": uid,
                    "name": _asset_name(asset),
                    "ipv4": _first(asset.get("ipv4")),
                    "os": os_lookup.get(uid),
                    "last_seen": asset.get("last_seen"),
                    "pqc_findings": len(categories),
                    **compute_verdict(pqc_plugins, has_non_pqc_findings=has_non_pqc),
                }
            )

        _cache_set(cache_key, result)
        cached = result

    # Summary counts from full (unfiltered) cached list
    total_at_risk = sum(1 for a in cached if a["verdict_color"] == "red")
    quantum_safe  = sum(1 for a in cached if a["verdict_color"] == "green")
    review        = sum(1 for a in cached if a["verdict_color"] == "amber")
    no_data       = sum(1 for a in cached if a["verdict_color"] == "grey")

    result = list(cached)

    if search:
        s = search.lower()
        result = [
            a for a in result
            if s in (a.get("name") or "").lower()
            or s in (a.get("ipv4") or "").lower()
            or s in (a.get("os") or "").lower()
        ]

    if sort:
        reverse = sort.startswith("-")
        field = sort.lstrip("-")
        result = sorted(result, key=lambda a: (a.get(field) or ""), reverse=reverse)

    return {
        "assets": result,
        "total": len(result),
        "summary": {
            "total_at_risk": total_at_risk,
            "quantum_safe": quantum_safe,
            "review": review,
            "no_data": no_data,
        },
    }


# ─── Fleet stream endpoint (SSE) ─────────────────────────────────────────────
@app.get("/api/pqc-assets/stream")
def stream_pqc_assets():
    def generate():
        # Cache hit — stream all at once
        cached = _cache_get("pqc_assets")
        if cached:
            for a in cached:
                yield f"data: {json.dumps(a)}\n\n"
            summary = {
                "total_at_risk": sum(1 for a in cached if a["verdict_color"] == "red"),
                "quantum_safe":  sum(1 for a in cached if a["verdict_color"] == "green"),
                "review":        sum(1 for a in cached if a["verdict_color"] == "amber"),
                "no_data":       sum(1 for a in cached if a["verdict_color"] == "grey"),
            }
            yield f'data: {json.dumps({"done": True, "summary": summary})}\n\n'
            return

        tio = _get_tio()
        asset_store: Dict[str, dict] = {}
        NON_PQC_CATS = set(PLUGINS.keys()) - {"core_pqc"}

        # Phase 1: collect asset universe from all category batches
        for cat, group_plugins in PLUGINS.items():
            id_str = ",".join(str(p) for p in group_plugins.keys())
            try:
                for asset in tio.workbenches.vuln_assets(("plugin.id", "eq", id_str)):
                    uid = asset.get("id")
                    if not uid:
                        continue
                    if uid not in asset_store:
                        asset_store[uid] = {"info": asset, "categories": set(), "pqc_plugins": set()}
                    asset_store[uid]["categories"].add(cat)
            except Exception:
                pass

        for pid in [277650, 298387, 277653]:
            try:
                for asset in tio.workbenches.vuln_assets(("plugin.id", "eq", str(pid))):
                    uid = asset.get("id")
                    if uid in asset_store:
                        asset_store[uid]["pqc_plugins"].add(pid)
                    elif uid:
                        asset_store[uid] = {"info": asset, "categories": {"core_pqc"}, "pqc_plugins": {pid}}
            except Exception:
                pass

        # Phase 2: parallel OS enrichment — stream each asset as its info resolves
        def enrich(uid: str, data: dict) -> dict:
            try:
                info = tio.workbenches.asset_info(uid)
                os_val = _first(info.get("operating_system") or [])
            except Exception:
                os_val = None
            asset = data["info"]
            pqc_plugins = data["pqc_plugins"]
            categories = data["categories"]
            has_non_pqc = bool(categories & NON_PQC_CATS)
            return {
                "uuid": uid,
                "name": _asset_name(asset),
                "ipv4": _first(asset.get("ipv4")),
                "os": os_val,
                "last_seen": asset.get("last_seen"),
                "pqc_findings": len(categories),
                **compute_verdict(pqc_plugins, has_non_pqc_findings=has_non_pqc),
            }

        result = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(enrich, uid, data): uid for uid, data in asset_store.items()}
            for fut in as_completed(futures):
                try:
                    record = fut.result()
                    result.append(record)
                    yield f"data: {json.dumps(record)}\n\n"
                except Exception:
                    pass

        _cache_set("pqc_assets", result)
        summary = {
            "total_at_risk": sum(1 for a in result if a["verdict_color"] == "red"),
            "quantum_safe":  sum(1 for a in result if a["verdict_color"] == "green"),
            "review":        sum(1 for a in result if a["verdict_color"] == "amber"),
            "no_data":       sum(1 for a in result if a["verdict_color"] == "grey"),
        }
        yield f'data: {json.dumps({"done": True, "summary": summary})}\n\n'

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )



@app.get("/api/asset/{uuid}")
def get_asset_detail(uuid: str):
    cache_key = f"asset_{uuid}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    tio = _get_tio()

    # Asset info — fields: id, fqdn, hostname, netbios_name, ipv4,
    #                       operating_system, last_seen
    try:
        asset_info = tio.workbenches.asset_info(uuid)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Asset not found: {e}")

    # All vulns for this asset — each record: plugin_id (int), plugin_name,
    #                             severity (int 0-4), count (int)
    try:
        raw_vulns = list(tio.workbenches.asset_vulns(uuid))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching vulnerabilities: {e}")

    # Build plugin presence map
    plugin_ids_present: Set[int] = set()
    plugin_map: Dict[int, dict] = {}

    for vuln in raw_vulns:
        pid = vuln.get("plugin_id")
        if pid is None or pid not in ALL_PLUGIN_IDS:
            continue
        plugin_ids_present.add(pid)
        sev_int = vuln.get("severity", 0)
        plugin_map[pid] = {
            "id": pid,
            "name": PLUGIN_NAMES.get(pid) or vuln.get("plugin_name") or "",
            "category": PLUGIN_CATEGORY.get(pid, "other"),
            "severity": SEVERITY_NAMES.get(sev_int, str(sev_int)),
            "count": vuln.get("count", 1),
            "present": True,
        }

    # Mark absent plugins
    for pid in ALL_PLUGIN_IDS:
        if pid not in plugin_map:
            plugin_map[pid] = {
                "id": pid,
                "name": PLUGIN_NAMES.get(pid, ""),
                "category": PLUGIN_CATEGORY.get(pid, "other"),
                "present": False,
            }

    # Shor's cipher list from plugin 298387 — parsed into service groups
    shors_services: List[dict] = []
    shors_truncated = False
    shors_raw_output = ""
    shors_tenable_url = (
        f"https://cloud.tenable.com/app.html#/workbench/assets/{uuid}"
        "/vulnerabilities/all/vulnerabilities/current"
    )

    if 298387 in plugin_ids_present:
        raw_parts = []
        try:
            outputs = list(tio.workbenches.asset_vuln_output(uuid, 298387))
            for record in outputs:
                raw = record.get("plugin_output", "")
                raw_parts.append(raw)
                if "truncated" in raw.lower():
                    shors_truncated = True
        except Exception:
            try:
                resp = tio._api.get(
                    f"workbenches/assets/{uuid}/vulnerabilities/298387/outputs"
                ).json()
                for rec in resp.get("outputs", []):
                    raw = rec.get("plugin_output", "")
                    raw_parts.append(raw)
                    if "truncated" in raw.lower():
                        shors_truncated = True
            except Exception:
                pass

        shors_raw_output = "\n".join(raw_parts).strip()
        shors_services = _parse_shors_output(shors_raw_output)

    # Extract asset fields
    fqdns    = asset_info.get("fqdn")     or []
    hostnames = asset_info.get("hostname") or []
    netbios  = asset_info.get("netbios_name") or []
    ipv4s    = asset_info.get("ipv4")     or []
    os_list  = asset_info.get("operating_system") or []

    NON_PQC_IDS = {pid for cat, grp in PLUGINS.items() if cat != "core_pqc" for pid in grp}
    has_non_pqc = bool(plugin_ids_present & NON_PQC_IDS)

    result = {
        "uuid": uuid,
        "name": _first(fqdns + hostnames + netbios + ipv4s, "Unknown"),
        "ipv4": _first(ipv4s),
        "os": _first(os_list),
        "last_seen": asset_info.get("last_seen"),
        "fqdns": fqdns,
        "hostnames": hostnames,
        **compute_verdict(plugin_ids_present, has_non_pqc_findings=has_non_pqc),
        "plugins": {str(pid): data for pid, data in plugin_map.items()},
        "shors_services": shors_services,
        "shors_raw_output": shors_raw_output,
        "shors_truncated": shors_truncated,
        "shors_tenable_url": shors_tenable_url,
        "plugin_ids_present": sorted(plugin_ids_present),
    }

    _cache_set(cache_key, result)
    return result


# ─── Static files & page routes ──────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/asset")
def asset_page():
    return FileResponse("static/asset.html")


@app.get("/settings")
def settings_page():
    return FileResponse("static/settings.html")


@app.get("/setup")
def setup_page():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/settings", status_code=301)
