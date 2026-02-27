#!/usr/bin/env python3
"""
CMDB Generator Web Server — Elastic FIM Workshop
Serves a web UI and proxies all ES requests server-side (no CORS).

Usage:
    python3 cmdb_server.py [--port 8080] [--es http://localhost:30920] \
                           [--user elastic-rocks] [--pass splunk-sucks]
"""

import argparse
import json
import random
import string
import threading
import time
import urllib.request
import urllib.error
from base64 import b64encode
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULTS = {
    'es':     'http://localhost:30920',
    'kibana': 'http://localhost:30002',
    'user':   'elastic-rocks',
    'passwd': 'splunk-sucks',
    'index':  'logs-servicenow.event-default',
    'port':   8080,
}

# ── Data definitions ──────────────────────────────────────────────────────────
LINUX_DISTROS = [
    {'os': 'Red Hat Enterprise Linux 8',  'os_version': '8.8',  'cpu_name': 'Intel Xeon E5-2690',   'cpu_mfr': 'Intel'},
    {'os': 'Red Hat Enterprise Linux 9',  'os_version': '9.2',  'cpu_name': 'Intel Xeon Gold 6252', 'cpu_mfr': 'Intel'},
    {'os': 'Ubuntu 22.04 LTS',            'os_version': '22.04','cpu_name': 'AMD EPYC 7542',         'cpu_mfr': 'AMD'},
    {'os': 'Ubuntu 20.04 LTS',            'os_version': '20.04','cpu_name': 'Intel Xeon E5-2670',   'cpu_mfr': 'Intel'},
    {'os': 'CentOS Linux 7',              'os_version': '7.9',  'cpu_name': 'Intel Xeon E5-2650',   'cpu_mfr': 'Intel'},
    {'os': 'Amazon Linux 2',              'os_version': '2.0',  'cpu_name': 'AWS Graviton2',         'cpu_mfr': 'AWS'},
    {'os': 'SUSE Linux Enterprise 15',    'os_version': '15.4', 'cpu_name': 'AMD EPYC 7763',         'cpu_mfr': 'AMD'},
]
WINDOWS_DISTROS = [
    {'os': 'Windows Server 2022', 'os_version': '21H2', 'sp': 'KB5026870'},
    {'os': 'Windows Server 2019', 'os_version': '1809',  'sp': 'KB5026362'},
    {'os': 'Windows Server 2016', 'os_version': '1607',  'sp': 'KB5025723'},
    {'os': 'Windows 11 Pro',      'os_version': '22H2',  'sp': 'KB5027231'},
    {'os': 'Windows 10 Enterprise','os_version': '21H2', 'sp': 'KB5026361'},
]
SQL_PLATFORMS = [
    {'os': 'Windows Server 2022',        'os_version': '21H2', 'sql': 'Microsoft SQL Server 2022', 'edition': 'Enterprise'},
    {'os': 'Windows Server 2019',        'os_version': '1809',  'sql': 'Microsoft SQL Server 2019', 'edition': 'Standard'},
    {'os': 'Red Hat Enterprise Linux 8', 'os_version': '8.8',   'sql': 'Microsoft SQL Server 2022', 'edition': 'Developer'},
    {'os': 'Windows Server 2016',        'os_version': '1607',  'sql': 'Microsoft SQL Server 2017', 'edition': 'Enterprise'},
    {'os': 'Ubuntu 20.04 LTS',           'os_version': '20.04', 'sql': 'PostgreSQL 15',             'edition': 'Community'},
    {'os': 'Red Hat Enterprise Linux 9', 'os_version': '9.2',   'sql': 'MySQL 8.0',                 'edition': 'Community'},
    {'os': 'Windows Server 2019',        'os_version': '1809',  'sql': 'Oracle Database 19c',        'edition': 'Enterprise'},
]
CUSTOM_APPS = [
    'PaymentGateway','FraudDetector','CustomerPortal','InventoryMgr','OrderProcessor',
    'ShipmentTracker','AuthService','NotificationHub','ReportEngine','DataWarehouse',
    'ComplianceAudit','RiskScorer','ClaimsProcessor','PolicyEngine','UnderwriterAI',
    'LoanOrigination','CreditChecker','ACHProcessor','WireTransferSvc','KYCVerifier',
    'AMLScanner','TransactionMonitor','AlertManager','CaseWorkflow','InvestigationMgr',
    'DocumentVault','ESignatureSvc','WorkflowEngine','IntegrationBus','APIGateway',
    'IdentityProvider','SessionManager','AuditLogger','MetricsCollector','HealthDashboard',
    'BackupOrchestrator','DisasterRecovery','ConfigManager','DeploymentEngine','PatchMgr',
    'VulnScanner','SOCPlatform','ThreatIntel','SIEMConnector','EDRManager',
    'CertificateAuthority','SecretVault','FirewallOrchestrator','ZeroTrustGateway','MDMConsole',
]
DEPARTMENTS   = ['Finance','Engineering','Operations','Security','Compliance','HR','Legal','IT','Marketing','Sales']
LOCATIONS     = ['New York DC1','Chicago DC2','Austin DC3','Seattle DC4','London DC5','Frankfurt DC6','Singapore DC7','Toronto DC8']
ENVIRONMENTS  = ['Production','Staging','Development','QA','DR','UAT']
ENV_WEIGHTS   = [50,15,15,10,6,4]
STATUSES      = ['Installed','Retired','In Maintenance','On Order']
STAT_WEIGHTS  = [75,10,10,5]
CLASSIFICATIONS = ['Highly Confidential','Confidential','Internal Use','Public']
MANUFACTURERS   = ['Dell','HP','Lenovo','Supermicro','IBM']
MODELS          = ['PowerEdge R750','ProLiant DL380','ThinkSystem SR650']
CHANGE_TYPES    = ['new','modified','modified','modified','decommissioned']
SUPPORT_GROUPS  = ['Linux Admin','Windows Admin','Database Team','AppOps','SecOps','NetOps']

# ── Helpers ───────────────────────────────────────────────────────────────────
def rnd(lst):           return random.choice(lst)
def rndint(a,b):        return random.randint(a,b)
def weighted(lst,wts):  return random.choices(lst,weights=wts,k=1)[0]
def sys_id():           return ''.join(random.choices('0123456789abcdef',k=32))
def rand_ip():
    return f"{rnd(['10.10','10.20','10.30','172.16','192.168.1','192.168.2'])}.{rndint(1,254)}.{rndint(1,254)}"
def rand_date(days=30):
    d = datetime.now(timezone.utc) - timedelta(days=random.random()*days)
    return d.strftime('%Y-%m-%dT%H:%M:%SZ')
def now_ts():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
def kv(v, dv=None):
    return {'value': v, 'display_value': dv if dv is not None else str(v)}

def common_fields(host, ip, env, status, cls, cls_dv):
    return {
        'sys_id':              kv(sys_id()),
        'sys_class_name':      kv(cls, cls_dv),
        'sys_updated_on':      kv(rand_date(), rand_date()),
        'sys_updated_by':      kv('cmdb.sync','CMDB Sync'),
        'sys_created_by':      kv('cmdb.sync','CMDB Sync'),
        'host_name':           kv(host),
        'name':                kv(host),
        'fqdn':                kv(f'{host}.corp.internal'),
        'dns_domain':          kv('corp.internal'),
        'ip_address':          kv(ip),
        'environment':         kv(env.lower(), env),
        'classification':      kv(rnd(CLASSIFICATIONS)),
        'install_status':      kv(status),
        'department':          kv(rnd(DEPARTMENTS)),
        'location':            kv(rnd(LOCATIONS)),
        'manufacturer':        kv(rnd(MANUFACTURERS)),
        'model_id':            kv(rnd(MODELS)),
        'serial_number':       kv(f'SN-{sys_id()[:8].upper()}',''),
        'data_classification': kv(rnd(CLASSIFICATIONS)),
        'vulnerability_risk_score': {'value': rndint(0,100), 'display_value': str(rndint(0,100))},
        'vip':       {'value': env=='Production' and random.random()>0.7, 'display_value': env=='Production' and random.random()>0.7},
        'is_clustered': {'value': random.random()>0.7, 'display_value': random.random()>0.7},
    }

def base_doc(host, ct):
    return {
        '@timestamp':  now_ts(),
        'event':       {'module':'servicenow','dataset':'servicenow.event'},
        'data_stream': {'type':'logs','dataset':'servicenow.event','namespace':'default'},
        'tags':        ['cmdb','fim-workshop', ct],
        'servicenow':  {'event':{}},
    }

def make_linux(i, ct):
    d = rnd(LINUX_DISTROS)
    host = f"lnx-{rnd(['web','app','api','svc','db','mon','bkp','prx'])}-{i+1:03d}"
    ip = rand_ip(); env = weighted(ENVIRONMENTS,ENV_WEIGHTS); stat = weighted(STATUSES,STAT_WEIGHTS)
    ram = rnd([8192,16384,32768,65536,131072])
    doc = base_doc(host, ct)
    doc['servicenow']['event'] = {**common_fields(host,ip,env,stat,'cmdb_ci_linux_server','Linux Server'),
        'os':kv(d['os']),'os_version':kv(d['os_version']),'os_domain':kv('corp.internal'),
        'os_address_width':kv('64'),'cpu_name':kv(d['cpu_name']),'cpu_manufacturer':kv(d['cpu_mfr']),
        'cpu_count':kv(rnd([2,4,8,16,32,64])),'ram':kv(ram,f'{ram//1024} GB'),
        'disk_space':kv(rnd([100,250,500,1000,2000])),'support_group':kv('Linux Admin'),
        'assigned_to':kv(f'svc.linux.{env.lower()}',f'Linux {env} Team'),'windows_host':kv(False)}
    return doc, host, ip, 'linux', d['os'], env, stat

def make_windows(i, ct):
    d = rnd(WINDOWS_DISTROS)
    host = f"win-{rnd(['dc','fs','ws','iis','ad','rds'])}-{i+1:03d}"
    ip = rand_ip(); env = weighted(ENVIRONMENTS,ENV_WEIGHTS); stat = weighted(STATUSES,STAT_WEIGHTS)
    ram = rnd([8192,16384,32768,65536])
    doc = base_doc(host, ct)
    doc['servicenow']['event'] = {**common_fields(host,ip,env,stat,'cmdb_ci_win_server','Windows Server'),
        'os':kv(d['os']),'os_version':kv(d['os_version']),'os_service_pack':kv(d['sp']),
        'os_domain':kv('CORP'),'os_address_width':kv('64'),
        'cpu_name':kv(rnd(['Intel Xeon E5-2690','Intel Xeon Gold 6226R','AMD EPYC 7542'])),
        'cpu_manufacturer':kv(rnd(['Intel','AMD'])),'cpu_count':kv(rnd([4,8,16,32])),
        'ram':kv(ram,f'{ram//1024} GB'),'disk_space':kv(rnd([200,500,1000,2000])),
        'support_group':kv('Windows Admin'),'assigned_to':kv(f'svc.windows.{env.lower()}'),
        'windows_host':kv(True)}
    return doc, host, ip, 'windows', d['os'], env, stat

def make_sql(i, ct):
    p = rnd(SQL_PLATFORMS)
    host = f"sql-{rnd(['prd','stg','dev','rpt','dw','olap'])}-{i+1:03d}"
    ip = rand_ip(); env = weighted(ENVIRONMENTS,ENV_WEIGHTS); stat = weighted(STATUSES,STAT_WEIGHTS)
    ram = rnd([32768,65536,131072,262144])
    doc = base_doc(host, ct)
    doc['servicenow']['event'] = {**common_fields(host,ip,env,stat,'cmdb_ci_db_mssql_instance','Database Instance'),
        'os':kv(p['os']),'os_version':kv(p['os_version']),'platform_host':kv(p['sql']),
        'model_category':kv(p['edition']),'classification':kv('Highly Confidential'),
        'data_classification':kv('Highly Confidential'),'cpu_count':kv(rnd([8,16,32,64])),
        'ram':kv(ram,f'{ram//1024} GB'),'disk_space':kv(rnd([2000,5000,10000])),
        'support_group':kv('Database Team'),'vip':{'value':True,'display_value':True},
        'windows_host':kv('windows' in p['os'].lower())}
    return doc, host, ip, 'sql', f"{p['sql']} / {p['os']}", env, stat

def make_app(app_def, i, ct):
    ip = rand_ip(); env = weighted(ENVIRONMENTS,ENV_WEIGHTS); stat = weighted(STATUSES,STAT_WEIGHTS)
    plat = rnd(['Red Hat Enterprise Linux 8','Ubuntu 22.04 LTS','Windows Server 2022','Amazon Linux 2'])
    doc = base_doc(app_def['host'], ct)
    doc['servicenow']['event'] = {**common_fields(app_def['host'],ip,env,stat,'cmdb_ci_appl','Application'),
        'name':kv(app_def['name']),'os':kv(plat),'os_version':kv('1.0'),
        'model_category':kv('Custom Application'),'department':kv(app_def['department']),
        'support_group':kv('AppOps'),'assigned_to':kv('svc.appops','AppOps Team'),
        'cpu_count':kv(rnd([2,4,8])),'ram':kv(rnd([4096,8192,16384])),
        'disk_space':kv(rnd([50,100,250,500])),'windows_host':kv('windows' in plat.lower())}
    return doc, app_def['host'], ip, 'app', f"{app_def['name']} v{app_def['version']}", env, stat

# ── CMDB Snapshot (persists between runs) ────────────────────────────────────
SNAPSHOT_FILE = '/tmp/cmdb_snapshot.json'

def save_snapshot(records):
    try:
        with open(SNAPSHOT_FILE, 'w') as f:
            json.dump(records, f)
    except Exception as e:
        print(f"[warn] Could not save snapshot: {e}")

def load_snapshot():
    try:
        with open(SNAPSHOT_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def mutate_record(rec):
    """Take an existing snapshot record and simulate a realistic change to it."""
    change_field = rnd(['install_status', 'environment', 'ip_address', 'os_version',
                        'vulnerability_risk_score', 'department', 'location', 'support_group'])
    evt = rec['doc']['servicenow']['event']
    changed = [change_field]

    if change_field == 'install_status':
        new_val = rnd([s for s in STATUSES if s != evt.get('install_status', {}).get('value')])
        evt['install_status'] = kv(new_val)
    elif change_field == 'environment':
        new_env = weighted(ENVIRONMENTS, ENV_WEIGHTS)
        evt['environment'] = kv(new_env.lower(), new_env)
    elif change_field == 'ip_address':
        evt['ip_address'] = kv(rand_ip())
    elif change_field == 'os_version':
        current = evt.get('os_version', {}).get('value', '1.0')
        parts = current.split('.')
        parts[-1] = str(int(parts[-1]) + rndint(1, 5)) if parts[-1].isdigit() else '1'
        evt['os_version'] = kv('.'.join(parts))
    elif change_field == 'vulnerability_risk_score':
        evt['vulnerability_risk_score'] = {'value': rndint(0, 100), 'display_value': str(rndint(0, 100))}
    elif change_field == 'department':
        evt['department'] = kv(rnd(DEPARTMENTS))
    elif change_field == 'location':
        evt['location'] = kv(rnd(LOCATIONS))
    elif change_field == 'support_group':
        evt['support_group'] = kv(rnd(SUPPORT_GROUPS))

    # Always bump sys_updated_on
    evt['sys_updated_on'] = kv(now_ts(), now_ts())
    rec['doc']['@timestamp'] = now_ts()
    rec['doc']['tags'] = ['cmdb', 'fim-workshop', 'modified']
    rec['meta']['changeType'] = 'modified'
    rec['meta']['changed_fields'] = changed
    return rec

# ── Generation state ──────────────────────────────────────────────────────────
gen_state = {
    'running': False,
    'total': 0, 'done': 0, 'ok': 0, 'fail': 0,
    'log': [], 'records': [],
    'start_time': None,
}
gen_lock = threading.Lock()

def add_log(level, msg):
    with gen_lock:
        gen_state['log'].append({'level': level, 'msg': msg, 'ts': now_ts()})
        if len(gen_state['log']) > 500:
            gen_state['log'] = gen_state['log'][-500:]

# ── Elasticsearch ─────────────────────────────────────────────────────────────
def es_auth(user, passwd):
    return 'Basic ' + b64encode(f'{user}:{passwd}'.encode()).decode()

def es_get(cfg, path):
    req = urllib.request.Request(
        f"{cfg['es']}/{path}",
        headers={'Authorization': es_auth(cfg['user'], cfg['passwd'])}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def bulk_index(docs, cfg):
    body = ''
    for doc in docs:
        body += json.dumps({'create': {'_index': cfg['index']}}) + '\n'
        body += json.dumps(doc) + '\n'
    req = urllib.request.Request(
        f"{cfg['es']}/_bulk",
        data=body.encode(),
        headers={
            'Content-Type': 'application/x-ndjson',
            'Authorization': es_auth(cfg['user'], cfg['passwd']),
        },
        method='POST'
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        result = json.loads(r.read())
    ok = fail = 0
    errors = []
    for item in result.get('items', []):
        r = item.get('create', item.get('index', {}))
        if r.get('error'):
            fail += 1
            errors.append(r['error'].get('reason', str(r['error']))[:120])
        else:
            ok += 1
    return ok, fail, errors

# ── Generator thread ──────────────────────────────────────────────────────────
def build_apps(n):
    shuffled = random.sample(CUSTOM_APPS, min(n, len(CUSTOM_APPS)))
    apps = []
    for i in range(n):
        name = shuffled[i % len(shuffled)]
        apps.append({'name': name,
                     'host': f"app-{name.lower()[:12]}-{i+1:02d}",
                     'version': f"{rndint(1,5)}.{rndint(0,9)}.{rndint(0,20)}",
                     'department': rnd(DEPARTMENTS)})
    return apps

def run_generator(cfg, opts):
    with gen_lock:
        gen_state.update({'running':True,'done':0,'ok':0,'fail':0,'log':[],'records':[],'start_time':time.time()})

    total_hosts = min(opts.get('hosts', 200), 200)
    app_count   = min(opts.get('apps',  50),  50)
    host_slots  = total_hosts - app_count
    mode        = opts.get('mode', 'initial')
    delay_ms    = opts.get('delay', 50)
    batch_size  = opts.get('batch', 20)

    pct_sum   = opts.get('linux',40) + opts.get('windows',35) + opts.get('sql',25) or 100
    n_linux   = round(host_slots * opts.get('linux',40)   / pct_sum)
    n_windows = round(host_slots * opts.get('windows',35) / pct_sum)
    n_sql     = host_slots - n_linux - n_windows

    # ── Build plan based on mode ──────────────────────────────────────────────
    plan = []  # list of {'doc':..., 'meta':...}

    if mode in ('changes', 'decommission', 'mixed'):
        snapshot = load_snapshot()
        if not snapshot:
            add_log('warn', 'No snapshot found — running initial load first to build baseline')
            mode = 'initial'  # fall through to initial
        else:
            add_log('info', f"Loaded snapshot: {len(snapshot)} existing hosts")

    if mode == 'initial':
        apps = build_apps(app_count)

        def make_plan_item(kind, i, app=None):
            if kind == 'linux':
                doc, host, ip, typ, os_str, env, stat = make_linux(i, 'new')
            elif kind == 'windows':
                doc, host, ip, typ, os_str, env, stat = make_windows(i, 'new')
            elif kind == 'sql':
                doc, host, ip, typ, os_str, env, stat = make_sql(i, 'new')
            else:
                doc, host, ip, typ, os_str, env, stat = make_app(app, i, 'new')
            return {
                'doc': doc,
                'meta': {'host': host, 'ip': ip, 'type': typ,
                         'os': os_str, 'env': env, 'status': stat, 'changeType': 'new'}
            }

        for i in range(n_linux):   plan.append(make_plan_item('linux', i))
        for i in range(n_windows): plan.append(make_plan_item('windows', i))
        for i in range(n_sql):     plan.append(make_plan_item('sql', i))
        for i, app in enumerate(apps): plan.append(make_plan_item('app', i, app))
        random.shuffle(plan)
        add_log('info', f"Initial load — generating {len(plan)} new records")

    elif mode == 'changes':
        # Pick a random subset of existing hosts and mutate them
        n_change = min(len(snapshot), total_hosts)
        chosen = random.sample(snapshot, n_change)
        import copy
        for rec in chosen:
            plan.append(mutate_record(copy.deepcopy(rec)))
        add_log('info', f"Delta changes — mutating {len(plan)} existing hosts from snapshot")

    elif mode == 'decommission':
        # Mark a subset as Retired
        n_decom = min(len(snapshot), max(1, total_hosts // 4))
        chosen = random.sample(snapshot, n_decom)
        import copy
        for rec in chosen:
            r = copy.deepcopy(rec)
            r['doc']['servicenow']['event']['install_status'] = kv('Retired')
            r['doc']['servicenow']['event']['sys_updated_on'] = kv(now_ts(), now_ts())
            r['doc']['@timestamp'] = now_ts()
            r['doc']['tags'] = ['cmdb', 'fim-workshop', 'decommissioned']
            r['meta']['changeType'] = 'decommissioned'
            r['meta']['status'] = 'Retired'
            plan.append(r)
        add_log('info', f"Decommission sweep — retiring {len(plan)} hosts from snapshot")

    elif mode == 'mixed':
        # Half mutations of existing, half new hosts
        import copy
        n_existing = len(snapshot)
        n_mutate = min(n_existing, total_hosts // 2)
        n_new = total_hosts - n_mutate

        chosen = random.sample(snapshot, n_mutate)
        for rec in chosen:
            plan.append(mutate_record(copy.deepcopy(rec)))

        apps = build_apps(app_count)
        n_new_hosts = n_new - app_count
        n_new_linux   = round(n_new_hosts * opts.get('linux',40)   / pct_sum)
        n_new_windows = round(n_new_hosts * opts.get('windows',35) / pct_sum)
        n_new_sql     = n_new_hosts - n_new_linux - n_new_windows

        for i in range(n_new_linux):
            doc, host, ip, typ, os_str, env, stat = make_linux(i, 'new')
            plan.append({'doc': doc, 'meta': {'host': host, 'ip': ip, 'type': typ,
                          'os': os_str, 'env': env, 'status': stat, 'changeType': 'new'}})
        for i in range(n_new_windows):
            doc, host, ip, typ, os_str, env, stat = make_windows(i, 'new')
            plan.append({'doc': doc, 'meta': {'host': host, 'ip': ip, 'type': typ,
                          'os': os_str, 'env': env, 'status': stat, 'changeType': 'new'}})
        for i in range(n_new_sql):
            doc, host, ip, typ, os_str, env, stat = make_sql(i, 'new')
            plan.append({'doc': doc, 'meta': {'host': host, 'ip': ip, 'type': typ,
                          'os': os_str, 'env': env, 'status': stat, 'changeType': 'new'}})
        for i, app in enumerate(apps):
            doc, host, ip, typ, os_str, env, stat = make_app(app, i, 'new')
            plan.append({'doc': doc, 'meta': {'host': host, 'ip': ip, 'type': typ,
                          'os': os_str, 'env': env, 'status': stat, 'changeType': 'new'}})

        random.shuffle(plan)
        add_log('info', f"Mixed — {n_mutate} mutations + {n_new} new hosts = {len(plan)} total")

    total = len(plan)
    with gen_lock:
        gen_state['total'] = total

    # ── Ingest loop ───────────────────────────────────────────────────────────
    batch_docs = []
    batch_meta = []
    snapshot_accumulator = []

    for i, item in enumerate(plan):
        if not gen_state['running']:
            add_log('warn', 'Generation stopped by user')
            break

        batch_docs.append(item['doc'])
        batch_meta.append(item['meta'])
        if mode == 'initial':
            snapshot_accumulator.append(item)

        if len(batch_docs) >= batch_size or i == total - 1:
            try:
                ok, fail, errors = bulk_index(batch_docs, cfg)
                with gen_lock:
                    gen_state['ok']   += ok
                    gen_state['fail'] += fail
                    gen_state['done'] += len(batch_docs)
                    gen_state['records'].extend(batch_meta[-len(batch_docs):])

                add_log('ok', f"Batch [{gen_state['done']}/{total}] — {ok} indexed, {fail} failed")
                for e in errors[:2]:
                    add_log('err', f"  ↳ {e}")
            except Exception as e:
                with gen_lock:
                    gen_state['fail'] += len(batch_docs)
                    gen_state['done'] += len(batch_docs)
                add_log('err', f"Batch error: {e}")

            batch_docs = []
            batch_meta = []

            if delay_ms > 0:
                time.sleep(delay_ms / 1000)

    # Save snapshot after initial load
    if mode == 'initial' and snapshot_accumulator:
        save_snapshot(snapshot_accumulator)
        add_log('info', f"Snapshot saved — {len(snapshot_accumulator)} hosts stored for delta runs")

    elapsed = time.time() - gen_state['start_time']
    rate = gen_state['ok'] / elapsed if elapsed > 0 else 0
    add_log('ok', f"Complete — {gen_state['ok']} indexed, {gen_state['fail']} failed in {elapsed:.1f}s ({rate:.1f}/s)")
    with gen_lock:
        gen_state['running'] = False

# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CMDB Generator — Elastic FIM Workshop</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&family=Barlow+Condensed:wght@700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0e17;--sf:#0f1520;--sf2:#161e2e;--bd:#1e2d45;--ac:#00d4ff;--ac2:#ff6b35;--ac3:#7fff6b;--ac4:#ffcc00;--tx:#c8d8e8;--dim:#5a7a9a;--er:#ff4444;--mono:'Share Tech Mono',monospace;--ui:'Barlow',sans-serif;--hd:'Barlow Condensed',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:var(--ui);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
.scanline{position:fixed;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--ac),transparent);animation:scan 4s linear infinite;opacity:.4;pointer-events:none;z-index:10}
@keyframes scan{0%{top:0}100%{top:100vh}}
header{position:relative;z-index:1;padding:20px 32px 16px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:20px}
.logo{width:44px;height:44px;border:2px solid var(--ac);display:grid;place-items:center;clip-path:polygon(0 0,calc(100% - 8px) 0,100% 8px,100% 100%,8px 100%,0 calc(100% - 8px));background:rgba(0,212,255,.05)}
.logo svg{width:22px;height:22px;fill:none;stroke:var(--ac);stroke-width:2}
h1{font-family:var(--hd);font-size:1.6rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#fff;line-height:1}
.sub{font-size:.75rem;color:var(--dim);font-family:var(--mono);letter-spacing:.05em;margin-top:3px}
.hst{margin-left:auto;display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:.72rem;color:var(--dim)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);transition:all .3s}
.dot.ok{background:var(--ac3);box-shadow:0 0 8px var(--ac3)}
.dot.err{background:var(--er);box-shadow:0 0 8px var(--er)}
.dot.busy{background:var(--ac4);box-shadow:0 0 8px var(--ac4);animation:pulse .8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.wrap{position:relative;z-index:1;max-width:1400px;margin:0 auto;padding:20px 32px;display:grid;grid-template-columns:320px 1fr;gap:20px}
.card{background:var(--sf);border:1px solid var(--bd);clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px));padding:18px}
.ct{font-family:var(--hd);font-size:.68rem;letter-spacing:.15em;text-transform:uppercase;color:var(--ac);margin-bottom:14px;display:flex;align-items:center;gap:8px}
.ct::before{content:'';width:12px;height:1px;background:var(--ac)}
.fl{margin-bottom:12px}
.fl label{display:block;font-size:.68rem;font-family:var(--mono);color:var(--dim);text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
input[type=text],input[type=number],input[type=password],select{width:100%;background:var(--bg);border:1px solid var(--bd);color:var(--tx);font-family:var(--mono);font-size:.8rem;padding:7px 10px;outline:none;transition:border-color .2s}
input:focus,select:focus{border-color:var(--ac)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.dr{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.dl{font-family:var(--mono);font-size:.7rem;width:85px;flex-shrink:0}
.dl .os{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:4px}
input[type=range]{flex:1;-webkit-appearance:none;height:3px;background:var(--bd);outline:none;cursor:pointer}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:13px;height:13px;background:var(--ac);clip-path:polygon(50% 0%,100% 50%,50% 100%,0% 50%);cursor:pointer}
.dv{font-family:var(--mono);font-size:.7rem;color:var(--ac);width:30px;text-align:right}
.div{height:1px;background:linear-gradient(90deg,transparent,var(--bd),transparent);margin:10px 0}
.btn-main{width:100%;padding:14px;background:transparent;border:2px solid var(--ac);color:var(--ac);font-family:var(--hd);font-size:1.05rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;cursor:pointer;clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px));transition:all .2s;position:relative;overflow:hidden}
.btn-main::before{content:'';position:absolute;inset:0;background:var(--ac);opacity:0;transition:opacity .2s}
.btn-main:hover::before{opacity:.1}
.btn-main:disabled{border-color:var(--bd);color:var(--dim);cursor:not-allowed}
.btn-main span{position:relative;z-index:1}
.btn-sec{width:100%;padding:9px;background:transparent;border:1px solid var(--bd);color:var(--dim);font-family:var(--mono);font-size:.72rem;cursor:pointer;transition:all .2s;letter-spacing:.04em;margin-top:6px}
.btn-sec:hover{border-color:var(--ac2);color:var(--ac2)}
.sg{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:8px}
.sb{background:var(--bg);border:1px solid var(--bd);padding:9px 10px;text-align:center}
.sv{font-family:var(--mono);font-size:1.3rem;color:var(--ac);line-height:1;transition:all .3s}
.sv.g{color:var(--ac3)}.sv.o{color:var(--ac2)}.sv.y{color:var(--ac4)}
.sl{font-size:.62rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;font-family:var(--mono);margin-top:2px}
.pw{background:var(--bg);border:1px solid var(--bd);height:5px;overflow:hidden}
.pb{height:100%;background:linear-gradient(90deg,var(--ac),var(--ac3));width:0%;transition:width .4s}
.pt{margin-top:6px;font-family:var(--mono);font-size:.65rem;color:var(--dim);text-align:center}
.rp{display:flex;flex-direction:column;gap:16px}
.term{background:#060a10;border:1px solid var(--bd);height:360px;overflow-y:auto;padding:14px;font-family:var(--mono);font-size:.73rem;line-height:1.6}
.term::-webkit-scrollbar{width:3px}
.term::-webkit-scrollbar-thumb{background:var(--bd)}
.le{display:flex;gap:10px}
.ts{color:var(--dim);flex-shrink:0;font-size:.68rem}
.info{color:var(--ac)}.ok{color:var(--ac3)}.warn{color:var(--ac4)}.err{color:var(--er)}.dim2{color:var(--dim)}
.twrap{background:var(--sf);border:1px solid var(--bd);overflow:hidden}
.thbar{display:flex;align-items:center;justify-content:space-between;padding:11px 14px;border-bottom:1px solid var(--bd)}
.frow{display:flex;gap:6px;padding:8px 14px;border-bottom:1px solid var(--bd);background:var(--bg);flex-wrap:wrap}
.fb{padding:3px 9px;background:transparent;border:1px solid var(--bd);color:var(--dim);font-family:var(--mono);font-size:.65rem;cursor:pointer;letter-spacing:.04em;transition:all .15s}
.fb.a{border-color:var(--ac);color:var(--ac);background:rgba(0,212,255,.07)}
table{width:100%;border-collapse:collapse}
thead th{font-family:var(--mono);font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);padding:7px 10px;text-align:left;border-bottom:1px solid var(--bd);background:var(--bg)}
tbody tr{border-bottom:1px solid rgba(30,45,69,.5);transition:background .15s;animation:ri .25s ease forwards;opacity:0}
@keyframes ri{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
tbody tr:hover{background:rgba(0,212,255,.04)}
tbody td{padding:6px 10px;font-size:.72rem;font-family:var(--mono)}
.badge{display:inline-block;padding:1px 6px;font-size:.6rem;letter-spacing:.05em;text-transform:uppercase;border:1px solid}
.badge.linux{color:var(--ac3);border-color:rgba(127,255,107,.4)}
.badge.windows{color:var(--ac);border-color:rgba(0,212,255,.4)}
.badge.sql{color:var(--ac4);border-color:rgba(255,204,0,.4)}
.badge.app{color:var(--ac2);border-color:rgba(255,107,53,.4)}
.tscroll{max-height:320px;overflow-y:auto}
.tscroll::-webkit-scrollbar{width:3px}
.tscroll::-webkit-scrollbar-thumb{background:var(--bd)}
.toast{position:fixed;bottom:20px;right:20px;background:var(--sf2);border:1px solid var(--ac);padding:10px 18px;font-family:var(--mono);font-size:.75rem;color:var(--ac);z-index:100;clip-path:polygon(0 0,calc(100% - 8px) 0,100% 8px,100% 100%,0 100%);transform:translateY(16px);opacity:0;transition:all .3s}
.toast.show{transform:none;opacity:1}
.toast.er{border-color:var(--er);color:var(--er)}
</style>
</head>
<body>
<div class="scanline"></div>
<header>
  <div class="logo"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg></div>
  <div><h1>CMDB Generator</h1><div class="sub">Elastic FIM Workshop // ServiceNow Event Simulation</div></div>
  <div class="hst"><div class="dot" id="dot"></div><span id="connTxt">NOT CONNECTED</span>&nbsp;|&nbsp;<span id="esVer" style="color:var(--dim)">ES: —</span></div>
</header>

<div class="wrap">
  <div style="display:flex;flex-direction:column;gap:14px">

    <div class="card">
      <div class="ct">Elasticsearch Config</div>
      <div class="fl"><label>ES Endpoint</label><input type="text" id="esEp" value="ES_ENDPOINT_PLACEHOLDER"/></div>
      <div class="fl"><label>Kibana Endpoint</label><input type="text" id="kbEp" value="KIBANA_ENDPOINT_PLACEHOLDER"/></div>
      <div class="two">
        <div class="fl"><label>Username</label><input type="text" id="esU" value="ES_USER_PLACEHOLDER"/></div>
        <div class="fl"><label>Password</label><input type="password" id="esP" value="ES_PASS_PLACEHOLDER"/></div>
      </div>
      <div class="fl"><label>Target Index</label><input type="text" id="esIdx" value="ES_INDEX_PLACEHOLDER"/></div>
      <button class="btn-sec" onclick="testConn()">⬡ TEST CONNECTION</button>
    </div>

    <div class="card">
      <div class="ct">Generation Config</div>
      <div class="two">
        <div class="fl"><label>Total Hosts</label><input type="number" id="hosts" value="200" min="10" max="200"/></div>
        <div class="fl"><label>Custom Apps</label><input type="number" id="apps" value="50" min="5" max="50"/></div>
      </div>
      <div class="div"></div>
      <div style="font-size:.68rem;font-family:var(--mono);color:var(--dim);text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">Host Distribution</div>
      <div class="dr"><div class="dl"><span class="os" style="background:var(--ac3)"></span>Linux</div><input type="range" id="dL" min="0" max="100" value="40" oninput="updDist()"><div class="dv" id="dLv">40%</div></div>
      <div class="dr"><div class="dl"><span class="os" style="background:var(--ac)"></span>Windows</div><input type="range" id="dW" min="0" max="100" value="35" oninput="updDist()"><div class="dv" id="dWv">35%</div></div>
      <div class="dr"><div class="dl"><span class="os" style="background:var(--ac4)"></span>SQL</div><input type="range" id="dS" min="0" max="100" value="25" oninput="updDist()"><div class="dv" id="dSv">25%</div></div>
      <div class="div"></div>
      <div class="fl"><label>Change Mode</label>
        <select id="mode">
          <option value="initial">Initial Load — Full CMDB snapshot</option>
          <option value="changes">Delta Changes — Simulate modifications</option>
          <option value="mixed">Mixed — New hosts + changes</option>
          <option value="decommission">Decommission Sweep</option>
        </select>
      </div>
      <div class="fl"><label>Delay between batches (ms)</label><input type="number" id="delay" value="50" min="0" max="5000"/></div>
    </div>

    <div class="card">
      <div class="ct">Session Stats</div>
      <div class="sg">
        <div class="sb"><div class="sv" id="sTot">0</div><div class="sl">Generated</div></div>
        <div class="sb"><div class="sv g" id="sOk">0</div><div class="sl">Indexed OK</div></div>
        <div class="sb"><div class="sv o" id="sFail">0</div><div class="sl">Failures</div></div>
        <div class="sb"><div class="sv y" id="sRate">0/s</div><div class="sl">Rate</div></div>
      </div>
      <div class="pw"><div class="pb" id="pb"></div></div>
      <div class="pt" id="pt">Ready</div>
    </div>

    <button class="btn-main" id="btnGen" onclick="startGen()"><span>⬢ GENERATE &amp; INGEST CMDB</span></button>
    <button class="btn-sec" onclick="stopGen()">■ STOP</button>
    <button class="btn-sec" onclick="clearLog()">⌫ CLEAR LOG</button>
    <button class="btn-sec" onclick="openKibana()">⬡ OPEN KIBANA DISCOVER</button>
  </div>

  <div class="rp">
    <div style="background:var(--sf);border:1px solid var(--bd)">
      <div class="thbar"><div class="ct" style="margin:0">Ingest Log</div><div id="logCnt" style="font-family:var(--mono);font-size:.65rem;color:var(--dim)">0 entries</div></div>
      <div class="term" id="term"><div class="le"><span class="ts">--:--:--</span><span class="dim2">Server-side generator ready. Press TEST CONNECTION then GENERATE.</span></div></div>
    </div>

    <div class="twrap">
      <div class="thbar"><div class="ct" style="margin:0">Generated Records</div><div id="recCnt" style="font-family:var(--mono);font-size:.65rem;color:var(--dim)">0 records</div></div>
      <div class="frow">
        <button class="fb a" onclick="setF('all',this)">ALL</button>
        <button class="fb" onclick="setF('linux',this)">LINUX</button>
        <button class="fb" onclick="setF('windows',this)">WINDOWS</button>
        <button class="fb" onclick="setF('sql',this)">SQL</button>
        <button class="fb" onclick="setF('app',this)">APPS</button>
      </div>
      <div class="tscroll">
        <table><thead><tr><th>Host Name</th><th>Type</th><th>OS / Platform</th><th>IP</th><th>Env</th><th>Status</th><th>Change</th></tr></thead>
        <tbody id="tbl"></tbody></table>
      </div>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
let polling = null;
let lastLogLen = 0;
let lastRecLen = 0;
let allRecs = [];
let activeF = 'all';

function ts() {
  const d = new Date();
  return [d.getHours(),d.getMinutes(),d.getSeconds()].map(n=>String(n).padStart(2,'0')).join(':');
}
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

async function testConn() {
  setDot('busy','CONNECTING...');
  try {
    const r = await fetch('/api/test');
    const d = await r.json();
    if (d.ok) {
      setDot('ok','CONNECTED');
      document.getElementById('esVer').textContent = `ES: ${d.version}`;
      addLog('ok', `Connected to Elasticsearch ${d.version} — cluster: ${d.cluster}`);
      toast(`Connected — ES ${d.version}`);
    } else {
      setDot('err','ERROR');
      addLog('err', `Connection failed: ${d.error}`);
      toast(d.error, true);
    }
  } catch(e) { setDot('err','ERROR'); addLog('err', e.message); toast(e.message, true); }
}

async function startGen() {
  document.getElementById('btnGen').disabled = true;
  lastLogLen = 0; lastRecLen = 0; allRecs = [];
  document.getElementById('tbl').innerHTML = '';

  const opts = {
    hosts:   parseInt(document.getElementById('hosts').value),
    apps:    parseInt(document.getElementById('apps').value),
    linux:   parseInt(document.getElementById('dL').value),
    windows: parseInt(document.getElementById('dW').value),
    sql:     parseInt(document.getElementById('dS').value),
    mode:    document.getElementById('mode').value,
    delay:   parseInt(document.getElementById('delay').value),
  };

  try {
    await fetch('/api/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(opts)});
    polling = setInterval(pollStatus, 800);
  } catch(e) { addLog('err', e.message); document.getElementById('btnGen').disabled = false; }
}

function stopGen() {
  fetch('/api/stop', {method:'POST'});
  addLog('warn', 'Stop requested...');
}

async function pollStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();

    // Update stats
    document.getElementById('sTot').textContent  = d.done;
    document.getElementById('sOk').textContent   = d.ok;
    document.getElementById('sFail').textContent = d.fail;
    const elapsed = d.elapsed || 0.001;
    document.getElementById('sRate').textContent = `${(d.ok/elapsed).toFixed(1)}/s`;
    const pct = d.total > 0 ? Math.round((d.done/d.total)*100) : 0;
    document.getElementById('pb').style.width = `${pct}%`;
    document.getElementById('pt').textContent = `${d.done} / ${d.total} (${pct}%)`;
    document.getElementById('recCnt').textContent = `${d.records_count} records`;

    // New log entries
    if (d.log && d.log.length > lastLogLen) {
      for (let i=lastLogLen; i<d.log.length; i++) {
        const e = d.log[i];
        addLog(e.level, e.msg, e.ts);
      }
      lastLogLen = d.log.length;
    }

    // New records
    if (d.records && d.records.length > lastRecLen) {
      for (let i=lastRecLen; i<d.records.length; i++) {
        allRecs.push(d.records[i]);
        addRow(d.records[i]);
      }
      lastRecLen = d.records.length;
    }

    if (!d.running) {
      clearInterval(polling);
      document.getElementById('btnGen').disabled = false;
      setDot('ok', 'COMPLETE');
      toast(`Done! ${d.ok}/${d.done} records indexed`);
    }
  } catch(e) { /* ignore poll errors */ }
}

function addLog(level, msg, tsStr) {
  const term = document.getElementById('term');
  const e = document.createElement('div');
  e.className = 'le';
  e.innerHTML = `<span class="ts">${tsStr ? tsStr.substring(11,19) : ts()}</span><span class="${level === 'ok' ? 'ok' : level === 'err' ? 'err' : level === 'warn' ? 'warn' : level === 'info' ? 'info' : 'dim2'}">${esc(msg)}</span>`;
  term.appendChild(e);
  term.scrollTop = term.scrollHeight;
  const cnt = term.children.length;
  document.getElementById('logCnt').textContent = `${cnt} entries`;
}

function clearLog() {
  document.getElementById('term').innerHTML = '';
  document.getElementById('logCnt').textContent = '0 entries';
  lastLogLen = 0;
}

function addRow(rec) {
  if (activeF !== 'all' && rec.type !== activeF) return;
  const tb = document.getElementById('tbl');
  const tr = document.createElement('tr');
  const ct = rec.changeType === 'new' ? `<span style="color:var(--ac3)">NEW</span>` :
             rec.changeType === 'modified' ? `<span style="color:var(--ac4)">MOD</span>` :
             `<span style="color:var(--er)">DECOM</span>`;
  tr.innerHTML = `<td>${rec.host}</td><td><span class="badge ${rec.type}">${rec.type}</span></td>
    <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(rec.os)}">${esc(rec.os)}</td>
    <td>${rec.ip}</td><td>${rec.env}</td><td>${rec.status}</td><td>${ct}</td>`;
  tb.insertBefore(tr, tb.firstChild);
  while(tb.children.length > 200) tb.removeChild(tb.lastChild);
}

function setF(f, btn) {
  activeF = f;
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('a'));
  btn.classList.add('a');
  const tb = document.getElementById('tbl');
  tb.innerHTML = '';
  allRecs.filter(r => f==='all' || r.type===f).slice(-200).forEach(r=>addRow(r));
}

function updDist() {
  document.getElementById('dLv').textContent = document.getElementById('dL').value + '%';
  document.getElementById('dWv').textContent = document.getElementById('dW').value + '%';
  document.getElementById('dSv').textContent = document.getElementById('dS').value + '%';
}

function setDot(state, txt) {
  document.getElementById('dot').className = `dot ${state}`;
  document.getElementById('connTxt').textContent = txt;
}

function toast(msg, er=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast${er?' er':''} show`;
  setTimeout(()=>t.className=`toast${er?' er':''}`, 3500);
}

function openKibana() {
  window.open(document.getElementById('kbEp').value + '/app/discover', '_blank');
}
</script>
</body>
</html>
"""

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    cfg = {}

    def log_message(self, fmt, *args):
        pass  # suppress access log

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ('/', '/index.html', '/cmdb_generator.html'):
            self.send_html(self.cfg['html'])

        elif path == '/api/test':
            try:
                data = es_get(self.cfg, '')
                self.send_json(200, {
                    'ok': True,
                    'version': data.get('version', {}).get('number', '?'),
                    'cluster': data.get('cluster_name', '?'),
                })
            except Exception as e:
                self.send_json(200, {'ok': False, 'error': str(e)})

        elif path == '/api/status':
            with gen_lock:
                elapsed = time.time() - gen_state['start_time'] if gen_state['start_time'] else 0.001
                self.send_json(200, {
                    'running':       gen_state['running'],
                    'total':         gen_state['total'],
                    'done':          gen_state['done'],
                    'ok':            gen_state['ok'],
                    'fail':          gen_state['fail'],
                    'elapsed':       round(elapsed, 2),
                    'log':           gen_state['log'],
                    'records':       gen_state['records'],
                    'records_count': len(gen_state['records']),
                })
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path

        if path == '/api/generate':
            if gen_state['running']:
                self.send_json(409, {'error': 'Already running'})
                return
            opts = self.read_body()
            t = threading.Thread(target=run_generator, args=(self.cfg, opts), daemon=True)
            t.start()
            self.send_json(200, {'ok': True})

        elif path == '/api/stop':
            with gen_lock:
                gen_state['running'] = False
            self.send_json(200, {'ok': True})

        else:
            self.send_response(404)
            self.end_headers()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description='CMDB Generator Web Server')
    p.add_argument('--port',   type=int, default=DEFAULTS['port'])
    p.add_argument('--es',     default=DEFAULTS['es'])
    p.add_argument('--kibana', default=DEFAULTS['kibana'])
    p.add_argument('--user',   default=DEFAULTS['user'])
    p.add_argument('--pass',   dest='passwd', default=DEFAULTS['passwd'])
    p.add_argument('--index',  default=DEFAULTS['index'])
    args = p.parse_args()

    # Inject config into HTML
    html = HTML \
        .replace('ES_ENDPOINT_PLACEHOLDER', args.es) \
        .replace('KIBANA_ENDPOINT_PLACEHOLDER', args.kibana) \
        .replace('ES_USER_PLACEHOLDER', args.user) \
        .replace('ES_PASS_PLACEHOLDER', args.passwd) \
        .replace('ES_INDEX_PLACEHOLDER', args.index)

    cfg = {
        'es': args.es, 'kibana': args.kibana,
        'user': args.user, 'passwd': args.passwd,
        'index': args.index, 'html': html,
    }
    Handler.cfg = cfg

    import socket
    local_ip = socket.gethostbyname(socket.gethostname())

    print(f"\n\033[1m\033[0;36m{'━'*56}\033[0m")
    print(f"\033[1m  CMDB Generator Web Server — Elastic FIM Workshop\033[0m")
    print(f"\033[0;36m{'━'*56}\033[0m\n")
    print(f"  \033[0;32mURL:\033[0m  http://localhost:{args.port}/")
    print(f"        http://{local_ip}:{args.port}/")
    print(f"  \033[0;36mES: \033[0m  {args.es}")
    print(f"  \033[0;36mIdx:\033[0m  {args.index}\n")
    print(f"  Press Ctrl+C to stop\n")

    server = HTTPServer(('', args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n\nServer stopped.')

if __name__ == '__main__':
    main()
