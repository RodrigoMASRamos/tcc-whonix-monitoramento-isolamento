#!/usr/bin/env bash
# Monitor do Cenário 4: iniciar com bash, inclusive em pasta compartilhada.
# O Python 3 embutido usa somente a biblioteca padrão para processar os registros.
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3 não encontrado. Envie esta mensagem para revisão.' >&2
    exit 1
fi
CENARIO04_SCRIPT_FILE="${BASH_SOURCE[0]}" exec python3 - "$@" <<'PYTHON_CENARIO04'
import argparse
import hashlib
import base64
import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time

SCRIPT_VERSION = '1.7'
BR = dt.timezone(dt.timedelta(hours=-3), 'Brasilia')
STEPS = {
    1: 'dnsleaktest - Extended Test',
    2: 'browserleaks - IP Address (incluindo DNS Leak Test)',
    3: 'browserleaks - WebRTC',
    4: 'browserleaks - Canvas Fingerprinting',
    5: 'browserleaks - WebGL',
    6: 'browserleaks - Font Fingerprinting',
    7: 'browserleaks - TLS',
    8: 'coveryourtracks - Test Your Browser',
    9: 'Teste de isolamento da Workstation (HTTPS e ICMP)',
}
LISTENER_ARGS = ['tor-ctrl', '-w', 'SETEVENTS', 'CIRC', 'CIRC_MINOR', 'STREAM', 'ORCONN']

BASE_KEYS = ('circuit-status', 'stream-status', 'orconn-status', 'entry-guards', 'ns/all')


def read_script_identity():
    name = os.environ.get('CENARIO04_SCRIPT_FILE', '')
    result = {'arquivo': str(Path(name).resolve()) if name else '', 'sha256_inicio': '',
              'sha256_fim': '', 'estado': 'indisponivel'}
    try:
        if not name:
            raise OSError('Caminho do script não informado pelo Bash.')
        result['sha256_inicio'] = hashlib.sha256(Path(name).read_bytes()).hexdigest()
        result['estado'] = 'calculado-no-inicio'
    except OSError as exc:
        result['erro'] = str(exc)
    return result


SCRIPT_IDENTITY = read_script_identity()


def final_script_identity():
    result = dict(SCRIPT_IDENTITY)
    try:
        if not result['sha256_inicio']:
            return result
        result['sha256_fim'] = hashlib.sha256(Path(result['arquivo']).read_bytes()).hexdigest()
        result['estado'] = ('inalterado' if result['sha256_inicio'] == result['sha256_fim'] else 'alterado')
    except OSError as exc:
        result['estado'] = 'nao-conferido-no-fim'
        result['erro'] = str(exc)
    return result


def checksum_panel(identity):
    lines = ['============ SHA-256 DO SCRIPT ============',
             'Arquivo: ' + identity['arquivo'],
             'SHA-256 registrado no início desta execução:',
             identity['sha256_inicio'] or 'Indisponível: não foi possível ler o arquivo.']
    if identity['estado'] == 'inalterado':
        lines.append('>>> Conferência final: o arquivo permanece igual ao início.')
    elif identity['estado'] == 'alterado':
        lines += ['>>> ATENÇÃO: o arquivo foi alterado durante a execução.',
                  'SHA-256 do arquivo ao encerrar:', identity['sha256_fim']]
    elif identity['estado'] == 'nao-conferido-no-fim':
        lines.append('>>> Não foi possível reler o arquivo ao encerrar; preserve o hash inicial.')
    if identity.get('erro'):
        lines.append('>>> Detalhe: ' + identity['erro'])
    lines.append('Compare o SHA-256 com o arquivo correspondente disponibilizado no repositório.')
    return '\n'.join(lines)


def wireshark_filters(guards):
    """Apenas o filtro 02 depende dos guardas confirmados da sessão."""
    ips = set()
    for g in guards:
        if g['ipv4']:
            ips.add(('ip.addr', g['ipv4']))
        ips.update(('ipv6.addr', ip) for ip in g['ipv6'])
    dynamic = ' or '.join(f'{kind} == {ip}' for kind, ip in sorted(ips))
    return (
        'tls',
        dynamic or None,
        'tls.handshake.type == 1',
        'tls.handshake.extensions_server_name contains "dnsleaktest.com"',
        'tls.handshake.extensions_server_name contains "browserleaks"',
        'tls.handshake.extensions_server_name contains "coveryourtracks"',
        'http.host contains "coveryourtracks"',
        'dns',
        'ipv6',
    )


def wireshark_panel(guards):
    separator = '-' * 66
    lines = ['FILTROS DE EXIBIÇÃO PARA COPIAR NO WIRESHARK:',
             'Aplique um por vez. Copie apenas o filtro, sem [ NN ].', separator]
    for number, expression in enumerate(wireshark_filters(guards), 1):
        lines.append(f'[ {number:02d} ] ' + (expression or
            'Indisponível: nenhum endereço de guarda confirmado.'))
    lines.extend([separator,
        'Filtro 02: conexões confirmadas pelo Tor; endereços anunciados para conferir na captura.',
        'A lista inclui guardas que foram desconectados depois. Nenhuma conexão é apagada do histórico.',
        'Os demais filtros examinam a captura inteira, que pode conter tráfego do host.',
        'Ausência de resultados, por si só, não indica falha do monitor.'])
    return '\n'.join(lines)


def clocks():
    n = dt.datetime.now(dt.timezone.utc)
    return {'brasilia': n.astimezone(BR).isoformat(timespec='milliseconds'),
            'utc': n.isoformat(timespec='milliseconds'), 'epoch_ms': int(n.timestamp() * 1000)}


def stamp(c=None):
    c = c or clocks()
    return f"{c['brasilia']} UTC={c['utc']} epoch_ms={c['epoch_ms']}"


def human_time(c):
    value = dt.datetime.fromisoformat(c['brasilia'])
    return value.strftime('%d/%m/%Y às %H:%M:%S') + f'.{value.microsecond // 1000:03d}, horário de Brasília'


def valid_getinfo(text, key, returncode=0):
    # Os números dentro de um bloco 250+ são dados (p.ex. stream 434), não códigos.
    inside = False
    found = False
    complete = False
    for line in text.splitlines():
        if inside:
            if line == '.':
                inside = False
            continue
        if re.match(r'^[45]\d\d[ -]', line):
            return False
        if line.startswith('250+'):
            inside = True
            if line.startswith('250+' + key + '='):
                found = True
        elif line.startswith('250-' + key + '='):
            found = True
        elif line.startswith('250 ' + key + '='):
            found = complete = True
        elif found and line == '250 OK':
            complete = True
    return returncode == 0 and found and complete and not inside


def letter_value(s):
    n = 0
    for c in s:
        n = n * 26 + ord(c) - 96
    return n


def letter_name(n):
    s = ''
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(97 + r) + s
    return s


def scan_indices(folder, base):
    rx = re.compile(re.escape(base) + r'-([a-z]+)-.+')
    found = set()
    for p in folder.iterdir():
        m = rx.fullmatch(p.name)
        if m:
            found.add(m[1])
        elif p.is_dir() and re.fullmatch(r'[A-Z]+', p.name):
            found.add(p.name.lower())
    return sorted(found, key=letter_value)


def getinfo_body(text, key):
    """Preserva a resposta bruta; extrai somente o corpo da chave solicitada."""
    result, inside = [], False
    for line in text.splitlines():
        if line.startswith('250+' + key + '='):
            inside = True
            value = line.split('=', 1)[1]
            if value:
                result.append(value)
        elif inside:
            if line == '.':
                inside = False
            else:
                result.append(line[1:] if line.startswith('..') else line)
        elif line.startswith(('250-' + key + '=', '250 ' + key + '=')):
            result.append(line.split('=', 1)[1])
    return result


def node_id(token):
    m = re.fullmatch(r'\$([0-9A-Fa-f]{40})(?:[~=]([^, ]+))?', token)
    return (m[1].upper(), m[2] or '') if m else ('', token)


def family(target):
    host = target.rsplit(':', 1)[0].strip('[]').lower().rstrip('.')
    for domain in ('dnsleaktest.com', 'browserleaks.com', 'coveryourtracks.eff.org'):
        if host == domain or host.endswith('.' + domain):
            return domain
    return ''


def safe_display(s):
    return ''.join(c for c in str(s) if c >= ' ' and c != '\x7f')


def run_query(key):
    proc = subprocess.Popen(['tor-ctrl', 'GETINFO', key], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8',
        errors='replace', start_new_session=True)
    try:
        text, _ = proc.communicate(timeout=45 if key == 'ns/all' else 15)
        return proc.returncode, text
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        text, _ = proc.communicate()
        return 124, text + '\nERRO_LOCAL: tempo limite da consulta.\n'
    finally:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()


class Tracker:
    def __init__(self):
        self.guard = threading.RLock()
        self.generation = 0
        self.stage = 0
        self.selected = set()
        self.circuits = {}
        self.streams = {}
        self.relays = {}
        self.observations = []
        self.event_count = 0
        self.stream_events = 0
        self.first_stream = None
        self.first_test_stream = None
        self.conflux_links = {}
        self.or_connections = {}
        self.first_hops = set()

    def new_generation(self):
        with self.guard:
            self.generation += 1
            return self.generation

    def circuit(self, body, generation, clock=None, minor=False):
        fields = body.split()
        if len(fields) < 2:
            return
        key = (generation, fields[0])
        clock = clock or clocks()
        if fields[1] == 'LAUNCHED':
            self.circuits.pop(key, None)
        entry = self.circuits.setdefault(key, {'path': [], 'status': '', 'raw': ''})
        attrs = dict(re.findall(r'\b(PURPOSE|CONFLUX_ID|TIME_CREATED)=([^ ]+)', body))
        # Guarda a associação observada, mesmo quando o circuito fechar depois.
        conflux_id = attrs.get('CONFLUX_ID', entry.get('conflux_id', ''))
        if attrs.get('PURPOSE') == 'CONFLUX_LINKED' and conflux_id:
            self.conflux_links[(generation, fields[0], conflux_id)] = clock['brasilia']
        if clock['epoch_ms'] < entry.get('updated', -1):
            return
        entry.update(updated=clock['epoch_ms'], observed=clock['brasilia'], raw=body)
        if not minor:
            entry['status'] = fields[1]
        if 'PURPOSE' in attrs:
            entry['purpose'] = attrs['PURPOSE']
        if conflux_id:
            entry['conflux_id'] = conflux_id
        if len(fields) > 2 and fields[2].startswith('$'):
            path = fields[2].split(',')
            # CLOSED/FAILED não apagam o percurso já observado.
            entry['path'] = path
            fp, _ = node_id(path[0])
            if fp and len(path) >= 2 and 'ONEHOP_TUNNEL' not in body:
                self.first_hops.add((generation, fp))

    def or_connection(self, body, generation, clock, origin):
        fields = body.split()
        if len(fields) < 2:
            return
        fp, nickname = node_id(fields[0])
        if not fp:
            return
        status = fields[1]
        entry = self.or_connections.setdefault((generation, fp), {
            'fingerprint': fp, 'nickname': nickname, 'connected': False,
            'first_confirmed': '', 'evidence': set(), 'last_status': status})
        if status == 'CONNECTED':
            entry['connected'] = True
            if not entry['first_confirmed']:
                entry['first_confirmed'] = clock['brasilia']
            entry['evidence'].add(origin)
        if clock['epoch_ms'] >= entry.get('updated', -1):
            entry.update(last_status=status, updated=clock['epoch_ms'])

    def guard_summary(self):
        # Cumulativo: fechar uma conexão não apaga a evidência da sessão.
        observations, relays = self.data()
        associations = self.associated_paths(observations)
        battery = {node_id(a['path'][0])[0] for a in associations.values()
                   if a['path'] and any(d != 'outro-ou-nao-identificado' for d in a['domains'])}
        guards = {}
        with self.guard:
            for (gen, fp), c in self.or_connections.items():
                if not c['connected'] or (gen, fp) not in self.first_hops:
                    continue
                desc = relays.get(fp, {})
                entry = guards.setdefault(fp, {'fingerprint': fp, 'name': desc.get('name', c['nickname']),
                    'ipv4': desc.get('ipv4', ''), 'ipv6': list(desc.get('ipv6', [])),
                    'first_confirmed': c['first_confirmed'], 'battery': fp in battery,
                    'evidence': set()})
                entry['evidence'].update(c['evidence'])
                entry['first_confirmed'] = min(entry['first_confirmed'], c['first_confirmed'])
        return sorted(guards.values(), key=lambda item: (item['first_confirmed'], item['fingerprint']))

    def stream(self, body, generation, clock, origin):
        fields = body.split()
        if len(fields) < 4:
            return
        sid, status, cid, target = fields[:4]
        key = (generation, sid)
        meta = self.streams.setdefault(key, {'original': target, 'source': '',
                                            'start_stage': self.stage})
        if status in ('NEW', 'NEWRESOLVE'):
            meta.update(original=target, start_stage=self.stage)
        for item in fields[4:]:
            if item.startswith('SOURCE_ADDR='):
                meta['source'] = item.split('=', 1)[1]
        if origin == 'evento':
            self.stream_events += 1
            if self.first_stream is None:
                self.first_stream = dict(clock, target=meta['original'])
            if family(meta['original']) and self.first_test_stream is None:
                self.first_test_stream = dict(clock, target=meta['original'])
        if status == 'SUCCEEDED' and cid != '0':
            circuit = self.circuits.get((generation, cid), {})
            self.observations.append(dict(clock, generation=generation,
                stage=self.stage, start_stage=meta['start_stage'], stream=sid,
                circuit=cid, target_original=meta['original'], target_current=target,
                source=meta['source'], origin=origin, family=family(meta['original']),
                path=list(circuit.get('path', []))))

    def consume(self, raw, generation, clock):
        with self.guard:
            m = re.match(r'^650[ -](CIRC|CIRC_MINOR|STREAM|ORCONN)\s+(.*)', raw)
            if not m:
                return
            self.event_count += 1
            kind, body = m.groups()
            if kind in ('CIRC', 'CIRC_MINOR'):
                self.circuit(body, generation, clock, minor=(kind == 'CIRC_MINOR'))
            elif kind == 'ORCONN':
                self.or_connection(body, generation, clock, 'evento-ORCONN-CONNECTED')
            elif kind == 'STREAM':
                self.stream(body, generation, clock, 'evento')

    def consensus(self, lines):
        current = None
        for line in lines:
            f = line.split()
            if f and f[0] == 'r' and len(f) >= 9:
                current = None
                try:
                    ident = base64.b64decode(f[2] + '=' * (-len(f[2]) % 4), validate=True)
                    if len(ident) != 20:
                        continue
                    fp = ident.hex().upper()
                    ipaddress.ip_address(f[6])
                    current = {'name': f[1], 'ipv4': f[6], 'port': f[7], 'ipv6': []}
                    self.relays[fp] = current
                except (ValueError, TypeError):
                    continue
            elif f and f[0] == 'a' and len(f) > 1 and current is not None:
                addr = f[1].rsplit(':', 1)[0].strip('[]')
                try:
                    if ipaddress.ip_address(addr).version == 6:
                        current['ipv6'].append(addr)
                except ValueError:
                    pass

    def ingest_snapshot(self, key, lines, generation, clock, origin):
        with self.guard:
            if key == 'circuit-status':
                for line in lines:
                    # Atualiza atributos (incluindo Conflux); eventos mais recentes têm prioridade.
                    self.circuit(line, generation, clock)
            elif key == 'stream-status':
                for line in lines:
                    self.stream(line, generation, clock, origin)
            elif key == 'orconn-status':
                for line in lines:
                    self.or_connection(line, generation, clock, origin)
            elif key == 'ns/all':
                self.consensus(lines)

    def data(self):
        with self.guard:
            observations = []
            for old in self.observations:
                row = dict(old)
                row['path_origin'] = 'conhecido-na-observacao'
                if not row['path']:
                    row['path'] = list(self.circuits.get((row['generation'], row['circuit']), {}).get('path', []))
                    row['path_origin'] = 'recuperado-na-mesma-conexao-de-controle' if row['path'] else 'nao-identificado'
                observations.append(row)
            return observations, {fp: dict(v) for fp, v in self.relays.items()}

    def associated_paths(self, observations):
        """Relações da sessão, sem afirmar distribuição de bytes por perna Conflux."""
        with self.guard:
            associations = {}
            for obs in observations:
                if not obs['path']:
                    continue
                key = (obs['generation'], obs['circuit'])
                a = associations.setdefault(key, {'path': obs['path'], 'domains': set(),
                    'origins': set(), 'relations': set(), 'groups': set(), 'direct_circuits': set()})
                a['domains'].add(obs['family'] or 'outro-ou-nao-identificado')
                a['origins'].add(obs['origin'])
                a['relations'].add('direta-STREAM-SUCCEEDED')
                a['direct_circuits'].add(obs['circuit'])
            direct = [(key, dict(value, domains=set(value['domains']), origins=set(value['origins'])))
                      for key, value in associations.items()]
            for (generation, cid), info in direct:
                groups = {group for gen, member, group in self.conflux_links if gen == generation and member == cid}
                for group in groups:
                    associations[(generation, cid)]['groups'].add(group)
                    for gen, sibling, sibling_group in self.conflux_links:
                        if gen != generation or sibling_group != group or sibling == cid:
                            continue
                        entry = self.circuits.get((gen, sibling), {})
                        if not entry.get('path'):
                            continue
                        a = associations.setdefault((gen, sibling), {'path': list(entry['path']),
                            'domains': set(), 'origins': set(), 'relations': set(),
                            'groups': set(), 'direct_circuits': set()})
                        a['domains'].update(info['domains'])
                        a['origins'].add('vinculo-CONFLUX_LINKED-observado-na-sessao')
                        a['relations'].add('associada-Conflux-sem-contagem-de-bytes')
                        a['groups'].add(group)
                        a['direct_circuits'].add(cid)
            return associations


class Monitor:
    def __init__(self, folder, prefix):
        self.folder, self.prefix = folder, prefix
        self.tracker = Tracker()
        self.io_lock = threading.RLock()
        self.messages = []
        self.proc = None
        self.thread = None
        self.expected_stop = False
        self.ack = threading.Event()
        self.reader_done = threading.Event()
        self.problem = ''
        self.finished = False
        self.started = clocks()
        self.tty = None
        self.identity = dict(SCRIPT_IDENTITY)
        self.proof_lock = threading.RLock()
        self.guard_proofs = {}
        self.descriptor_proofs = {}
        self.proofs_shown = set()
        self.query_trace = []
        self.listener_replies = []
        self.append('etapas.txt', f'{stamp()} INICIO modo={"teste" if "-teste-" in prefix else "coleta"}\n')
        self.append('ocorrencias.txt', f'{stamp()} INICIO Monitor {SCRIPT_VERSION}; relógio do host NÃO medido.\n')

    def path(self, suffix):
        return self.folder / f'{self.prefix}-{suffix}'

    def append(self, suffix, content):
        with self.io_lock:
            with self.path(suffix).open('a', encoding='utf-8', newline='') as file:
                file.write(content)

    def occurrence(self, text):
        self.append('ocorrencias.txt', f'{stamp()} {text}\n')

    def notify(self, text):
        with self.io_lock:
            self.messages.append(text)

    def drain(self):
        with self.io_lock:
            for msg in self.messages:
                print('\n>>> ' + safe_display(msg), flush=True)
            self.messages.clear()

    def present(self, title, lines):
        """Exibe os trechos em sequência; o registrador continua ativo."""
        lines = [str(line) for line in lines]
        self.append('evidencias.txt', '\n' + '=' * 66 + '\n' + title + '\n' +
                    '\n'.join(lines) + '\n')
        print('\n' + '=' * 66)
        print(title)
        print('-' * 66)
        for line in lines:
            print(safe_display(line))
        print('-' * 66, flush=True)

    def capture_evidence(self, key, lines, generation, clock, source, command):
        """Cópias literais para apresentação; não modifica a identificação dos guardas."""
        with self.proof_lock:
            if key == 'ns/all':
                current, block = None, []
                def save():
                    if current:
                        self.descriptor_proofs[current] = dict(
                            lines=list(block), source=source, command=command, clock=dict(clock))
                for line in lines:
                    fields = line.split()
                    if fields and fields[0] == 'r':
                        save()
                        current, block = None, []
                        try:
                            identity = base64.b64decode(fields[2] + '=' * (-len(fields[2]) % 4), validate=True)
                            if len(identity) == 20:
                                current, block = identity.hex().upper(), [line]
                        except (ValueError, IndexError):
                            pass
                    elif current and fields and fields[0] == 'a':
                        block.append(line)
                save()
                return
            for raw in lines:
                kind, body = key, raw
                if key == 'evento':
                    match = re.match(r'^650[ -](ORCONN|CIRC|CIRC_MINOR)\s+(.*)', raw)
                    if not match:
                        continue
                    kind, body = match.groups()
                fields = body.split()
                if len(fields) < 2:
                    continue
                record = dict(lines=[raw], source=source, command=command, clock=dict(clock))
                if kind in ('ORCONN', 'orconn-status') and fields[1] == 'CONNECTED':
                    fp, _ = node_id(fields[0])
                    if fp:
                        self.guard_proofs.setdefault((generation, fp), {}).setdefault('connection', record)
                elif kind in ('CIRC', 'CIRC_MINOR', 'circuit-status') and len(fields) > 2:
                    path = fields[2].split(',')
                    fp, _ = node_id(path[0])
                    if fp and len(path) >= 2 and 'ONEHOP_TUNNEL' not in body:
                        proof = self.guard_proofs.setdefault((generation, fp), {})
                        # Para a apresentação, prefere um circuito completo de três saltos.
                        rank = (fields[1] == 'BUILT', len(path) == 3,
                                bool(re.search(r'PURPOSE=(GENERAL|CONFLUX_)', body)))
                        if 'circuit' not in proof or rank > proof['rank']:
                            proof['circuit'] = record
                            proof['rank'] = rank

    def show_new_evidence(self):
        guards = self.tracker.guard_summary()
        for guard in guards:
            fp = guard['fingerprint']
            signature = (fp, guard['ipv4'], tuple(guard['ipv6']))
            if signature in self.proofs_shown:
                continue
            with self.proof_lock:
                proof = next((dict(value) for (gen, ident), value in self.guard_proofs.items()
                              if ident == fp and 'connection' in value and 'circuit' in value), None)
                descriptor = self.descriptor_proofs.get(fp)
            if not proof or not descriptor:
                # A falta de um trecho não deve impedir a coleta nem fabricar uma evidência.
                continue
            lines = ['Fingerprint: ' + fp]
            for label, record in [('1. CONEXÃO CONFIRMADA', proof['connection']),
                                  ('2. PRIMEIRO SALTO DE CIRCUITO', proof['circuit']),
                                  ('3. ENDEREÇO ANUNCIADO PELO TOR', descriptor)]:
                lines += ['', label, 'Comando de origem (já executado):',
                          '$ ' + record['command'], 'Trecho da resposta original:']
                lines += record['lines']
                lines += ['Fonte: ' + record['source'], 'Recebido: ' + human_time(record['clock'])]
            lines += ['', '>>> Interpretação: conexão confirmada + primeiro salto observado.',
                      '>>> Guarda: ' + guard['name'] + ' | IPv4 anunciado: ' + guard['ipv4'],
                      '>>> O fingerprint vincula o relay do circuito ao registro de endereço.',
                      '>>> Confira os endereços anunciados na captura do Wireshark.']
            self.present('EVIDÊNCIAS DO GUARDA | ' + guard['name'], lines)
            self.proofs_shown.add(signature)

    def query(self, key, suffix):
        started = clocks()
        returncode, text = run_query(key)
        self.append(suffix, f'\n{stamp(started)} COMANDO: tor-ctrl GETINFO {key}\n{text}\n')
        valid = valid_getinfo(text, key, returncode)
        body = getinfo_body(text, key) if valid else []
        self.query_trace.append((key, text, returncode, valid, len(body), suffix))
        if valid:
            self.capture_evidence(key, body, self.tracker.generation, started,
                                  self.path(suffix).name, shlex.join(['tor-ctrl', 'GETINFO', key]))
        if not valid:
            self.occurrence(f'CONSULTA_FALHOU chave={key}; consulte {self.path(suffix).name}')
            self.notify(f'ATENÇÃO: a consulta {key} não foi validada. O registro de eventos pode continuar; '
                        'preserve os arquivos para revisão. Não use R apenas por este aviso.')
        return getinfo_body(text, key) if valid else None, started

    def snapshot(self, suffix, keys=BASE_KEYS):
        success = True
        trace_start = len(self.query_trace)
        generation = self.tracker.generation
        for key in keys:
            lines, clock = self.query(key, suffix)
            if lines is None:
                success = False
            else:
                self.tracker.ingest_snapshot(key, lines, generation, clock, 'estado:' + suffix)
        display = ['Saída original: cabeçalho e conclusão de cada consulta (trechos).',
                   'Corpos completos: ' + self.path(suffix).name]
        for key, text, returncode, valid, count, _ in self.query_trace[trace_start:]:
            display += ['', '$ ' + shlex.join(['tor-ctrl', 'GETINFO', key])]
            if valid:
                raw_lines = text.splitlines()
                header = next(line for line in raw_lines if line.startswith(
                    ('250+' + key + '=', '250-' + key + '=', '250 ' + key + '=')))
                display.append(header)
                if header.startswith('250+'):
                    display.append(f'>>> {count} linha(s) de conteúdo; íntegra no arquivo indicado.')
                    display.append(next(line for line in reversed(raw_lines) if line == '250 OK'))
                elif '250 OK' in raw_lines:
                    display.append('250 OK')
                if not header.startswith('250+'):
                    display.append('>>> Consulta validada | retorno: ' + str(returncode))
            else:
                display += ['Resposta original (primeiras linhas):'] + text.splitlines()[:5]
                display += ['>>> Consulta não validada | retorno: ' + str(returncode)]
        self.present('COMANDOS E RESPOSTAS | ' + suffix, display)
        self.show_new_evidence()
        return success

    def start_listener(self):
        if self.proc is not None and self.proc.poll() is None:
            raise RuntimeError('Já existe um registrador ativo.')
        self.expected_stop = False
        self.problem = ''
        self.ack.clear()
        self.reader_done.clear()
        generation = self.tracker.new_generation()
        self.append('tor-eventos.log', f'{stamp()} CONTROLE_INICIO geracao={generation}\n')
        self.listener_replies = []
        self.present('COMANDO | MONITORAMENTO CONTÍNUO', [
            '$ ' + shlex.join(LISTENER_ARGS),
            '>>> CIRC/CIRC_MINOR: circuitos; STREAM: conexões; ORCONN: relays.',
            '>>> O comando permanece ativo enquanto você realiza os testes.',
            '>>> Saída completa: ' + self.path('tor-eventos.log').name])
        self.proc = subprocess.Popen(LISTENER_ARGS,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace', bufsize=1, start_new_session=True)
        proc = self.proc

        def read_events():
            try:
                for line in proc.stdout:
                    raw = line.rstrip('\r\n')
                    now = clocks()
                    self.append('tor-eventos.log', f'{stamp(now)} geracao={generation} {raw}\n')
                    if re.match(r'^[245]\d\d[ -]', raw):
                        with self.proof_lock:
                            if len(self.listener_replies) < 8:
                                self.listener_replies.append(raw)
                    if raw == '250 OK':
                        self.ack.set()
                    if re.match(r'^[45]\d\d[ -]', raw):
                        self.problem = 'Resposta de erro do controlador: ' + raw
                        self.notify(self.problem)
                    first = self.tracker.first_stream is None
                    first_test = self.tracker.first_test_stream is None
                    self.tracker.consume(raw, generation, now)
                    self.capture_evidence('evento', [raw], generation, now,
                                          self.path('tor-eventos.log').name, shlex.join(LISTENER_ARGS))
                    got_first = first and self.tracker.first_stream is not None
                    got_test = first_test and self.tracker.first_test_stream is not None
                    if got_first:
                        self.occurrence('PRIMEIRO_STREAM_OBSERVADO (origem do programa não comprovada)')
                    if got_test:
                        self.occurrence('PRIMEIRO_STREAM_PARA_DOMINIO_DA_BATERIA')
                    if got_first and got_test:
                        self.notify('Primeiro STREAM recebido, já para um domínio da bateria: ' + human_time(now) + '.')
                    elif got_first:
                        self.notify('Primeiro STREAM recebido: ' + human_time(now) + '.')
                    elif got_test:
                        self.notify('Primeiro STREAM para um domínio da bateria: ' + human_time(now) + '.')
                    orm = re.match(r'^650 ORCONN (\S+) (CONNECTED|CLOSED|FAILED)\b(.*)', raw)
                    if orm:
                        fp, nick = node_id(orm[1])
                        name = safe_display(nick or fp or orm[1])
                        reason = re.search(r'REASON=(\S+)', orm[3])
                        detail = ' Motivo: ' + reason[1] + '.' if reason else ''
                        self.occurrence('ORCONN_AUTOMATICO ' + raw[4:])
                        if orm[2] == 'CONNECTED':
                            self.notify('Conexão com relay ' + name + ' estabelecida. Registro automático; não é necessário usar R.')
                        else:
                            self.notify('Conexão com relay ' + name + ' encerrada ou falhou.' + detail +
                                ' O registrador continua ativo; não use R apenas por este evento.')
            except Exception as exc:
                self.problem = f'Falha ao gravar/processar eventos: {exc}'
                self.notify(self.problem)
            finally:
                self.reader_done.set()
                if not self.expected_stop:
                    self.problem = self.problem or 'O fluxo de eventos terminou. Há uma lacuna de monitoramento.'
                    self.notify(self.problem + ' Use R para reconectar o registrador, ou F para encerrar.')
                    try:
                        self.occurrence('LACUNA_INICIO ' + self.problem)
                    except OSError:
                        pass

        self.thread = threading.Thread(target=read_events, daemon=True)
        self.thread.start()
        limit = time.monotonic() + 15
        while time.monotonic() < limit:
            if self.ack.wait(.1):
                # Dá tempo para uma eventual negativa de SETEVENTS após autenticação.
                time.sleep(.15)
                with self.proof_lock:
                    replies = list(self.listener_replies)
                self.present('RESPOSTA | MONITORAMENTO CONTÍNUO',
                             ['Trecho da saída original:'] + replies +
                             ['>>> Os eventos seguintes serão gravados continuamente.'])
                return self.healthy()
            if self.reader_done.is_set():
                break
        self.problem = self.problem or 'Não foi recebido 250 OK em 15 segundos.'
        return False

    def healthy(self):
        return self.proc is not None and self.proc.poll() is None and not self.reader_done.is_set() and not self.problem

    def stop_listener(self):
        self.expected_stop = True
        if self.proc is None:
            return
        # Mata apenas o grupo de tor-ctrl criado por este script, nunca o serviço Tor.
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=3)
            except ProcessLookupError:
                pass
        if self.thread:
            self.thread.join(timeout=5)
        if self.proc.stdin:
            self.proc.stdin.close()
        if self.proc.stdout and self.reader_done.is_set():
            self.proc.stdout.close()

    def status(self):
        self.drain()
        self.show_new_evidence()
        t = self.tracker
        print('\nMonitoramento:', 'ATIVO' if self.healthy() else 'COM FALHA / INTERROMPIDO')
        print('Etapa atual:', STEPS.get(t.stage, 'nenhuma marcada'))
        print(f'Eventos: {t.event_count} | STREAM: {t.stream_events}')
        now = dt.datetime.fromisoformat(clocks()['brasilia'])
        print('Data:', now.strftime('%d/%m/%Y'))
        print('Horário:', now.strftime('%H:%M:%S'))
        print('UTC: -03:00 (horário de Brasília)')
        if t.first_stream:
            print('Primeiro STREAM observado:', human_time(t.first_stream))
        else:
            print('Ainda não chegou um STREAM. Isso não é, por si só, erro.')
        self.show_guards()
        print('Pasta:', self.folder)
        print('Sessão:', self.prefix)
        if self.healthy():
            if t.stage == 9:
                print('>>> Ação agora: execute o teste de isolamento na Workstation.')
                print('>>> Mantenha este monitor aberto; finalize-o com F após terminar os testes.')
            elif t.stage == 8 and 9 not in t.selected:
                print('>>> Ao terminar Cover Your Tracks, marque 9 antes de iniciar o isolamento.')
            elif len(t.selected) == len(STEPS):
                print('Ação agora: conclua os testes e use F; o registro continua sozinho até lá.')
            else:
                print('Ação agora: marque a próxima etapa antes de abrir o teste; o registro continua sozinho.')
        else:
            print('AÇÃO NECESSÁRIA: preserve o aviso; use R após restabelecer o Tor, ou F para encerrar.')

    def show_guards(self, final=False):
        guards = self.tracker.guard_summary()
        lines = []
        if not guards:
            lines.append('Ainda não há guarda confirmado pelas conexões e pelos circuitos observados.')
        for n, g in enumerate(guards, 1):
            lines.append(f"[ {n} ] {safe_display(g['name'])} | IPv4: {g['ipv4'] or 'não identificado'}")
            lines.append('      Relação: ' + ('bateria de testes' if g['battery'] else 'outra atividade Tor observada'))
            if final:
                lines.append('      Fingerprint: ' + g['fingerprint'])
        if final:
            self.present('GUARDAS DA SESSÃO', lines)
            self.present('FILTROS PARA O WIRESHARK', wireshark_panel(guards).splitlines())
        else:
            print('\nGUARDAS COM CONEXÃO CONFIRMADA NA SESSÃO')
            print('\n'.join(lines))

    def mark_step(self, number, ask):
        t = self.tracker
        pending = [n for n in STEPS if n not in t.selected]
        if number not in pending:
            print('Etapa inexistente ou já selecionada.')
            return False
        if not self.healthy():
            print('O registrador está interrompido. Reconecte com R antes de marcar uma etapa.')
            return False
        out_of_order = number != pending[0]
        if out_of_order and ask(f'A próxima esperada é {pending[0]}. Iniciar {number} fora de ordem? [s/N] ').lower() != 's':
            return False
        with t.guard:
            when = clocks()
            previous = t.stage
            if previous:
                self.append('etapas.txt', f'{stamp(when)} FIM_DA_JANELA etapa={previous:02d} (início da próxima etapa; conclusão do teste não verificada)\n')
            t.stage = number
            t.selected.add(number)
            self.append('etapas.txt', f'{stamp(when)} INICIO_MANUAL etapa={number:02d} nome={STEPS[number]} fora_de_ordem={out_of_order}\n')
        self.snapshot('tor-estados-etapas.txt', ('circuit-status', 'stream-status'))
        self.write_reports()
        if number == 9:
            self.present('ETAPA 09 | TESTE DE ISOLAMENTO DA WORKSTATION', [
                '>>> No terminal da Workstation, execute:',
                'bash /media/sf_cenario04/scripts/cenario04_workstation_isolamento.sh',
                '>>> Execute HTTPS e ICMP; depois, finalize o script da Workstation.',
                '>>> Por último, volte a este terminal e use F para exibir os filtros.',
                '>>> O monitor continua registrando os guardas durante os testes.'])
        else:
            print('Etapa registrada. Você pode iniciar o teste na Workstation.')
        return True

    def write_reports(self):
        observations, relays = self.tracker.data()
        connection_fields = ['brasilia', 'utc', 'epoch_ms', 'generation', 'stage', 'start_stage',
            'stream', 'circuit', 'target_original', 'target_current', 'source', 'family', 'origin', 'path_origin', 'path']
        # Relatórios derivados podem ser regenerados; registros brutos são append-only.
        with self.path('conexoes.tsv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=connection_fields, delimiter='\t', extrasaction='ignore')
            w.writeheader()
            for row in observations:
                w.writerow(dict(row, path=','.join(row['path'])))
        relay_fields = ['geracao', 'circuito', 'posicao', 'papel', 'fingerprint', 'apelido',
                        'ipv4_anunciado', 'porta_or_anunciada', 'ipv6_anunciados', 'dominios',
                        'origens', 'relacoes', 'grupos_conflux', 'circuitos_stream_diretos']
        associations = self.tracker.associated_paths(observations)
        filter_ips = set()
        with self.path('relays.tsv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=relay_fields, delimiter='\t')
            w.writeheader()
            for (gen, cid), info in sorted(associations.items()):
                for pos, token in enumerate(info['path']):
                    fp, nick = node_id(token)
                    desc = relays.get(fp, {})
                    role = 'primeiro-relay' if pos == 0 else ('ultimo-relay' if pos == len(info['path']) - 1 else 'intermediario')
                    w.writerow({'geracao': gen, 'circuito': cid, 'posicao': pos + 1, 'papel': role,
                        'fingerprint': fp, 'apelido': desc.get('name', nick), 'ipv4_anunciado': desc.get('ipv4', ''),
                        'porta_or_anunciada': desc.get('port', ''), 'ipv6_anunciados': ','.join(desc.get('ipv6', [])),
                        'dominios': ','.join(sorted(info['domains'])), 'origens': ','.join(sorted(info['origins'])),
                        'relacoes': ','.join(sorted(info['relations'])), 'grupos_conflux': ','.join(sorted(info['groups'])),
                        'circuitos_stream_diretos': ','.join(sorted(info['direct_circuits']))})
                    if pos == 0 and any(domain != 'outro-ou-nao-identificado' for domain in info['domains']):
                        if desc.get('ipv4'):
                            filter_ips.add(('ip.addr', desc['ipv4']))
                        for ipv6 in desc.get('ipv6', []):
                            filter_ips.add(('ipv6.addr', ipv6))
        with self.path('circuitos.tsv').open('w', encoding='utf-8', newline='') as f:
            w = csv.writer(f, delimiter='\t')
            w.writerow(['geracao', 'circuito', 'percurso', 'dominios', 'relacoes', 'grupos_conflux', 'circuitos_stream_diretos'])
            for (gen, cid), info in sorted(associations.items()):
                w.writerow([gen, cid, ','.join(info['path']), ','.join(sorted(info['domains'])),
                    ','.join(sorted(info['relations'])), ','.join(sorted(info['groups'])),
                    ','.join(sorted(info['direct_circuits']))])
        with self.path('vinculos-conflux.tsv').open('w', encoding='utf-8', newline='') as f:
            w = csv.writer(f, delimiter='\t')
            w.writerow(['geracao', 'circuito', 'grupo_conflux', 'observado_brasilia'])
            with self.tracker.guard:
                for (gen, cid, group), observed in sorted(self.tracker.conflux_links.items()):
                    w.writerow([gen, cid, group, observed])
        filter_text = ' or '.join(f'{kind} == {ip}' for kind, ip in sorted(filter_ips))
        self.path('filtro-guardas.txt').write_text(
            'Filtro auxiliar: endereços ANUNCIADOS dos primeiros relays de circuitos com STREAM\n'
            'SUCCEEDED para domínios da bateria, incluindo circuitos associados por Conflux.\n'
            'As relações e grupos estão em relays.tsv e circuitos.tsv. O vínculo Conflux não\n'
            'quantifica bytes transportados em cada percurso. Confirme os endereços no pcapng.\n'
            'Um endereço anunciado (especialmente IPv6) não comprova conexão por esse endereço.\n\n' +
            (filter_text or 'Nenhum endereço identificado com os dados disponíveis.') + '\n', encoding='utf-8')
        confirmed_guards = self.tracker.guard_summary()
        with self.path('guardas-sessao.txt').open('w', encoding='utf-8') as f:
            f.write('Guardas com conexão confirmada (ORCONN/estado CONNECTED + primeiro salto de circuito).\n')
            f.write('Lista cumulativa; endereços anunciados para conferir no Wireshark.\n\n')
            for g in confirmed_guards:
                f.write(f"{g['name']} | IPv4: {g['ipv4']} | fingerprint: {g['fingerprint']}\n")
                f.write('Relação: ' + ('bateria' if g['battery'] else 'outra atividade Tor') + '\n')
            f.write('\n' + wireshark_panel(confirmed_guards) + '\n')
            if self.finished:
                f.write('\n' + checksum_panel(self.identity) + '\n')
        summary = {
            'script': SCRIPT_VERSION, 'identificacao_script': self.identity, 'inicio': self.started, 'atualizado': clocks(),
            'prefixo': self.prefix, 'pasta': str(self.folder), 'finalizado': self.finished,
            'etapas_marcadas': sorted(self.tracker.selected),
            'etapas_nao_marcadas': [n for n in STEPS if n not in self.tracker.selected],
            'primeiro_stream_observado': self.tracker.first_stream,
            'primeiro_stream_dominio_bateria': self.tracker.first_test_stream,
            'diferenca_relogio_host': 'não medida; exibir UTC-3 não mede o relógio do Windows',
            'observacoes': [
                'Horários de recepção local no Gateway; o relógio e o fuso do sistema não são modificados.',
                'Marcar uma etapa registra intenção e janela temporal; não comprova conclusão do teste.',
                'STREAM não informa caminho HTTPS nem programa de origem. Source address é preservado quando disponível.',
                'Estados de etapas podem mostrar streams já abertos e reutilizados entre páginas.',
                'Relays: relação direta por STREAM SUCCEEDED ou associação Conflux observada na mesma sessão.',
                'Conflux não demonstra quantos bytes de cada stream passaram em cada percurso; consenso isolado não comprova uso.',
                'Interrupções de monitoramento podem deixar circuitos ou streams sem identificação.',
            ],
        }
        self.path('resumo.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    def finish(self, reason):
        if self.finished:
            return
        print('\nSalvando o estado final e encerrando o registrador...')
        try:
            self.occurrence('ENCERRAMENTO ' + reason)
            if self.tracker.stage:
                self.append('etapas.txt', f'{stamp()} FIM_DA_JANELA etapa={self.tracker.stage:02d} motivo=encerramento\n')
            # A inscrição continua ativa enquanto as consultas finais são feitas.
            self.snapshot('tor-final.txt')
        finally:
            self.stop_listener()
            self.finished = True
            self.identity = final_script_identity()
            self.write_reports()
        self.drain()
        self.show_new_evidence()
        self.show_guards(final=True)
        print('\n' + checksum_panel(self.identity))
        print('\nRegistros salvos em:', self.folder)
        print('Prefixo:', self.prefix)


def main():
    parser = argparse.ArgumentParser(prog='cenario04_gateway.sh', description='Cenário 4: monitor de circuitos Tor no Whonix-Gateway.',
                                     epilog='Execute como usuário normal: bash cenario04_gateway.sh')
    parser.add_argument('--ajuda', action='help', help='mostrar esta ajuda')
    parser.add_argument('--pasta', default='/media/sf_cenario04', help='pasta compartilhada já montada')
    parser.add_argument('--modo', choices=['teste', 'coleta'], help='pré-selecionar o tipo de sessão')
    parser.add_argument('--verificar', action='store_true', help='verificar dependências, escrita e acesso ao controlador; não inicia coleta')
    args = parser.parse_args()
    if not shutil.which('tor-ctrl'):
        raise RuntimeError('tor-ctrl não encontrado. Execute este arquivo no Whonix-Gateway.')
    root = Path(args.pasta).expanduser().resolve()
    if not root.is_dir():
        raise RuntimeError(f'A pasta compartilhada não existe: {root}. Confira a montagem.')
    folder_root = root / 'Registros' / 'Gateway'
    folder_root.mkdir(parents=True, exist_ok=True)
    lock = folder_root / '.monitor-gateway-em-uso'
    try:
        lock.mkdir()
    except FileExistsError:
        raise RuntimeError(f'Existe um bloqueio de sessão: {lock}. Feche o outro monitor. '
                           'Se a VM foi desligada abruptamente, remova essa pasta somente após confirmar que nenhum monitor está ativo.')
    monitor = None
    tty = None
    try:
        (lock / 'sessao.txt').write_text(f'PID={os.getpid()}\n{stamp()}\n', encoding='utf-8')
        if args.verificar:
            returncode, output = run_query('circuit-status')
            print(output)
            if not valid_getinfo(output, 'circuit-status', returncode):
                raise RuntimeError('Consulta não validada. Preserve a mensagem acima.')
            print('OK: Python 3, tor-ctrl, escrita na pasta e consulta de circuitos disponíveis.')
            print('Horário:', human_time(clocks()))
            print('Esta verificação não substitui um ensaio recebendo eventos reais de navegação.')
            return
        tty = open('/dev/tty', 'r', encoding='utf-8', buffering=1)

        def ask(prompt):
            print(prompt, end='', flush=True)
            while True:
                ready, _, _ = select.select([tty], [], [], 1)
                if ready:
                    line = tty.readline()
                    if not line:
                        raise EOFError('Terminal fechado.')
                    return line.strip()

        print('\nCENÁRIO 4 | MONITOR DO GATEWAY')
        print('Pasta compartilhada:', root)
        mode = None
        default_mode = '2' if args.modo == 'coleta' else '1'
        print('============ TIPO DE EXECUÇÃO ============')
        print('[ 1 ] Ensaio/teste\n[ 2 ] Coleta definitiva')
        while mode is None:
            answer = ask(f'Escolha o modo [{default_mode}]: ') or default_mode
            mode = {'1': 'teste', '2': 'coleta'}.get(answer)
        mode_folder = folder_root / ('Testes' if mode == 'teste' else 'Coletas')
        mode_folder.mkdir(exist_ok=True)
        base = 'cenario04-teste' if mode == 'teste' else 'cenario04'
        existing = scan_indices(mode_folder, base)
        next_index = letter_name(max((letter_value(x) for x in existing), default=0) + 1)
        print('Índices encontrados:', ', '.join(existing) or 'nenhum')
        print('Nova sessão sugerida:', base + '-' + next_index)
        while True:
            choice = ask('Enter = criar a próxima; ou digite uma letra existente para reescrever: ').lower()
            index = choice or next_index
            if index == next_index and not choice:
                break
            if index not in existing:
                print('Use Enter para a próxima tentativa ou uma das letras listadas.')
                continue
            prefix = f'{base}-{index}'
            print('Será substituído o conjunto de registros dessa tentativa. O anterior irá para Anteriores.')
            if ask(f'Digite REESCREVER {index} para confirmar: ') != f'REESCREVER {index}':
                continue
            previous = mode_folder / index.upper()
            legacy = list(mode_folder.glob(prefix + '-*'))
            if previous.is_symlink() or (previous.exists() and not previous.is_dir()):
                raise RuntimeError(f'Pasta de tentativa inválida: {previous}')
            for old in legacy:
                if old.is_symlink() or not old.is_file():
                    raise RuntimeError(f'Item inesperado com o prefixo escolhido: {old}; não foi substituído.')
            archive = mode_folder / 'Anteriores' / (prefix + '-' + dt.datetime.now(BR).strftime('%Y%m%d-%H%M%S-%f'))
            archive.mkdir(parents=True)
            if previous.exists():
                shutil.move(str(previous), str(archive / index.upper()))
            for old in legacy:
                shutil.move(str(old), str(archive / old.name))
            print('Registros anteriores preservados em:', archive)
            break
        prefix = f'{base}-{index}'
        folder = mode_folder / index.upper()
        folder.mkdir(exist_ok=False)
        print('Pasta dos registros:', folder)
        print('Prefixo dos arquivos:', prefix)
        ask('Deixe o Wireshark capturando no host. Pressione Enter para iniciar o registro: ')
        monitor = Monitor(folder, prefix)
        print('Conectando ao controlador Tor...')
        if not monitor.start_listener():
            raise RuntimeError(monitor.problem or 'O registro de eventos não iniciou.')
        print('Salvando o estado inicial...')
        monitor.snapshot('tor-inicial.txt')
        monitor.write_reports()
        while True:
            monitor.status()
            print('\n============ ETAPAS DISPONÍVEIS ============')
            pending = [n for n in STEPS if n not in monitor.tracker.selected]
            for n in pending:
                print(f'[ {n} ] {STEPS[n]}' + ('  [PRÓXIMA]' if n == pending[0] else ''))
            if not pending:
                print('Todas as etapas foram marcadas. Encerre somente depois de concluir os testes na Workstation.')
            print('-' * 66)
            print('O - Anotar ocorrência   S - Estado   R - Reconectar registrador   F - Finalizar')
            print('O (letra): se houve imprevisto. S: consulta opcional. R: somente se o registrador falhar.')
            print('Ao concluir a navegação e o isolamento, use F. O, S e R são opcionais.')
            print('-' * 66)
            option = ask('Opção: ').lower()
            monitor.drain()
            if option.isdecimal():
                monitor.mark_step(int(option), ask)
            elif option == 's':
                monitor.write_reports()
            elif option == 'o':
                print('1 - Interrupção  2 - Reconexão  3 - Reinicialização do Tor  4 - Outra ocorrência')
                kind = ask('Tipo: ')
                names = {'1': 'interrupcao', '2': 'reconexao', '3': 'reinicializacao-Tor', '4': 'outra'}
                if kind not in names:
                    print('Tipo inválido.')
                    continue
                description = ask('Descrição breve: ')
                monitor.occurrence(f'MANUAL tipo={names[kind]} etapa={monitor.tracker.stage:02d} descricao={description}')
                print('Ocorrência registrada.')
                if kind == '3':
                    print('Após reiniciar o Tor, use R para começar uma nova conexão de monitoramento.')
            elif option == 'r':
                if ask('Reconectar apenas o registrador? Isso não reinicia o Tor. [s/N] ').lower() == 's':
                    monitor.occurrence('RECONEXAO_REGISTRADOR solicitada; início de intervalo sem eventos')
                    monitor.stop_listener()
                    if monitor.start_listener():
                        monitor.snapshot('tor-reconexoes.txt')
                        monitor.occurrence('RECONEXAO_REGISTRADOR concluída; dados anteriores à nova inscrição podem faltar')
                    else:
                        print('Falha na reconexão:', monitor.problem)
                    monitor.write_reports()
            elif option == 'f':
                if pending and ask('Ainda há etapas não marcadas. Encerrar mesmo assim? [s/N] ').lower() != 's':
                    continue
                monitor.finish('opcao-F')
                break
            else:
                print('Opção inválida.')
    finally:
        try:
            if monitor and not monitor.finished:
                monitor.finish('interrupcao-ou-erro')
        finally:
            if monitor:
                monitor.stop_listener()
            if tty:
                tty.close()
            shutil.rmtree(lock)


def on_signal(signum, frame):
    raise KeyboardInterrupt


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\nSessão interrompida. Confira os arquivos e eventuais avisos acima.')
        sys.exit(130)
    except Exception as exc:
        print('\nERRO:', safe_display(exc), file=sys.stderr)
        print('Não considere a coleta validada sem conferir esse erro.', file=sys.stderr)
        sys.exit(1)
PYTHON_CENARIO04
