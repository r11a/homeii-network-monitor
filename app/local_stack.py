"""Single-add-on process supervisor. Linux image only; no runtime downloads."""
from __future__ import annotations
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import sqlite3
import subprocess
import time
from .zabbix import Client, Engine, EngineError

ROOT = Path(os.environ.get('HOMEII_DATA_DIR', '/data/homeii'))
PG_BIN = '/usr/lib/postgresql/15/bin/'
children = []
stopping = False


def private_file(path, content, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as handle: handle.write(content)
    if owner:
        account = pwd.getpwnam(owner)
        os.chown(path, account.pw_uid, account.pw_gid)


def identity(owner):
    if not owner: return {}
    account = pwd.getpwnam(owner)
    return {'user': account.pw_uid, 'group': account.pw_gid}


def run(args, owner=None, input=None):
    return subprocess.run(args, input=input, text=True, check=True, **identity(owner))


def start(args, owner=None):
    process = subprocess.Popen(args, **identity(owner))
    children.append(process)
    return process


def stop(_signum=None, _frame=None):
    global stopping
    stopping = True
    for child in reversed(children):
        if child.poll() is None: child.terminate()


def wait_until(check, timeout=180):
    deadline = time.monotonic() + timeout
    while not stopping and time.monotonic() < deadline:
        if any(p.poll() is not None for p in children): raise RuntimeError('A required local service stopped')
        try:
            if check(): return
        except (EngineError, OSError, subprocess.CalledProcessError): pass
        time.sleep(2)
    raise RuntimeError('Local engine initialization timed out; see add-on logs')


def preserve_legacy():
    source = ROOT / 'homeii.db'
    target = ROOT / 'backups' / 'homeii-before-bundled-zabbix.db'
    if source.exists() and not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(source) as incoming, sqlite3.connect(target) as outgoing:
            incoming.backup(outgoing)
            if outgoing.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise RuntimeError('Legacy backup failed verification')


def initialize():
    ROOT.mkdir(parents=True, exist_ok=True)
    preserve_legacy()
    secret_path = ROOT / 'local-engine-secrets.json'
    if secret_path.exists(): values = json.loads(secret_path.read_text())
    else:
        values = {'database': secrets.token_hex(32), 'administrator': secrets.token_urlsafe(40)}
        private_file(secret_path, json.dumps(values))
    pgdata = ROOT / 'postgres'
    pgdata.mkdir(mode=0o700, exist_ok=True)
    postgres = pwd.getpwnam('postgres')
    os.chown(pgdata, postgres.pw_uid, postgres.pw_gid)
    socket = Path('/run/homeii-postgres'); socket.mkdir(exist_ok=True)
    os.chown(socket, postgres.pw_uid, postgres.pw_gid)
    if not (pgdata / 'PG_VERSION').exists():
        run([PG_BIN+'initdb', '-D', str(pgdata), '--encoding=UTF8', '--locale=C.UTF-8', '--auth-local=peer', '--auth-host=scram-sha-256'], 'postgres')
    if (pgdata / 'PG_VERSION').read_text().strip() != '15':
        raise RuntimeError('PostgreSQL major-version migration required; data preserved')
    start([PG_BIN+'postgres', '-D', str(pgdata), '-h', '127.0.0.1', '-p', '15432', '-k', str(socket)], 'postgres')
    wait_until(lambda: subprocess.run([PG_BIN+'pg_isready', '-h', str(socket), '-p', '15432'], stdout=subprocess.DEVNULL).returncode == 0)
    sql = [PG_BIN+'psql', '-h', str(socket), '-p', '15432', '-v', 'ON_ERROR_STOP=1']
    run(sql+['-d', 'postgres'], 'postgres', "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='zabbix') THEN CREATE ROLE zabbix LOGIN; END IF; END $$;\nALTER ROLE zabbix PASSWORD '"+values['database']+"';\n")
    db_exists = subprocess.check_output(sql+['-d', 'postgres', '-tAc', "SELECT 1 FROM pg_database WHERE datname='zabbix'"], text=True, **identity('postgres')).strip()
    if not db_exists: run([PG_BIN+'createdb', '-h', str(socket), '-p', '15432', '-O', 'zabbix', 'zabbix'], 'postgres')
    initialized = subprocess.check_output(sql+['-d', 'zabbix', '-tAc', "SELECT to_regclass('public.dbversion') IS NOT NULL"], text=True, **identity('postgres')).strip() == 't'
    if not initialized:
        run(sql+['-d', 'zabbix', '--single-transaction', '-c', 'SET ROLE zabbix', '-f', '/opt/zabbix/database/schema.sql',
                 '-f', '/opt/zabbix/database/images.sql', '-f', '/opt/zabbix/database/data.sql'], 'postgres')
    private_file('/etc/zabbix/zabbix_server.conf',
        'DBHost=127.0.0.1\nDBPort=15432\nDBName=zabbix\nDBUser=zabbix\nDBPassword='+values['database']+
        '\nLogType=console\nPidFile=/var/lib/zabbix/server.pid\nListenIP=127.0.0.1\nListenPort=10051\n'
        'FpingLocation=/usr/bin/fping\nFping6Location=/usr/bin/fping\nStartPingers=5\nStartPollers=10\n'
        'StartDiscoverers=3\nCacheSize=64M\nHistoryCacheSize=32M\nTimeout=4\n', 'zabbix')
    private_file('/opt/zabbix/ui/conf/zabbix.conf.php',
        "<?php\n$DB['TYPE']='POSTGRESQL';\n$DB['SERVER']='127.0.0.1';\n$DB['PORT']='15432';\n"
        "$DB['DATABASE']='zabbix';\n$DB['USER']='zabbix';\n$DB['PASSWORD']='"+values['database']+"';\n"
        "$DB['SCHEMA']='';\n$ZBX_SERVER='127.0.0.1';\n$ZBX_SERVER_PORT='10051';\n$ZBX_SERVER_NAME='HOMEii local';\n", 'www-data')
    Path('/etc/php/8.2/fpm/conf.d/99-homeii.ini').write_text('memory_limit=256M\nmax_execution_time=60\ndate.timezone=UTC\n')
    start(['/usr/sbin/php-fpm8.2', '-F'])
    start(['/usr/sbin/nginx', '-g', 'daemon off;'])
    start(['/usr/local/sbin/zabbix_server', '-f', '-c', '/etc/zabbix/zabbix_server.conf'], 'zabbix')
    client = Client({'url': 'http://127.0.0.1:9081'})
    wait_until(lambda: client.call('apiinfo.version'))
    version = client.call('apiinfo.version')
    try: login = client.call('user.login', {'username': 'Admin', 'password': values['administrator'], 'userData': True})
    except EngineError:
        login = client.call('user.login', {'username': 'Admin', 'password': 'zabbix', 'userData': True})
        client.token = login['sessionid']
        client.call('user.update', {'userid': login['userid'], 'passwd': values['administrator']})
        login = client.call('user.login', {'username': 'Admin', 'password': values['administrator'], 'userData': True})
    client.token = login['sessionid']
    current = Engine(ROOT)
    if not client.call('template.get', {'filter': {'host': ['ICMP Ping']}, 'output': ['templateid']}):
        template = Path('/opt/zabbix/icmp_ping.yaml').read_text()
        client.call('configuration.import', {'format': 'yaml', 'source': template,
            'rules': {'template_groups': {'createMissing': True}, 'templates': {'createMissing': True},
                      'items': {'createMissing': True}, 'triggers': {'createMissing': True},
                      'graphs': {'createMissing': True}, 'valueMaps': {'createMissing': True}}})
    if not current.public_config()['configured']:
        tokenid = client.call('token.create', {'name': 'HOMEii local '+secrets.token_hex(4), 'userid': login['userid']})['tokenids'][0]
        token = client.call('token.generate', [tokenid])[0]['token']
        current.save_config({'url': client.url, 'token': token, 'verify_tls': True, 'version': version})
    default = client.call('host.get', {'filter': {'host': ['Zabbix server']}, 'output': ['hostid']})
    if default and not initialized:
        client.call('host.update', [{'hostid': host['hostid'], 'status': 1} for host in default])
    client.call('user.logout', [])
    print('[HOMEii] Local monitoring engine is ready. No Internet required.', flush=True)


def main():
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    try:
        initialize()
        options = json.loads(Path('/data/options.json').read_text()) if Path('/data/options.json').exists() else {}
        base = ['/opt/venv/bin/python', '-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--no-proxy-headers']
        if options.get('ssl'):
            cert = Path('/ssl') / Path(options.get('certfile', 'fullchain.pem')).name
            key = Path('/ssl') / Path(options.get('keyfile', 'privkey.pem')).name
            if not cert.is_file() or not key.is_file(): raise RuntimeError('Configured HTTPS certificate is missing')
            start(base+['--port', '8444', '--ssl-certfile', str(cert), '--ssl-keyfile', str(key)])
        start(base+['--port', '8384'])
        while not stopping:
            if any(p.poll() is not None for p in children): raise RuntimeError('A required service stopped')
            time.sleep(2)
    finally:
        stop()
        for child in reversed(children):
            try: child.wait(timeout=20)
            except subprocess.TimeoutExpired: child.kill(); child.wait()


if __name__ == '__main__': main()
