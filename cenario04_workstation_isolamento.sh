#!/usr/bin/env bash
# Execute com bash na Whonix-Workstation, como usuário normal.
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3 não encontrado.' >&2
    exit 1
fi
CENARIO04_SCRIPT_FILE="${BASH_SOURCE[0]}" exec python3 - "$@" <<'PYTHON_ISOLAMENTO'
import argparse
import hashlib
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import shutil
import socket
import subprocess
import sys
import time

VERSION = '1.3'
BR = dt.timezone(dt.timedelta(hours=-3))
LINE = '-' * 68
URL = 'https://check.torproject.org/api/ip'
TARGET = '1.1.1.1'
TITLES = {'https': 'HTTPS sem proxy explícito', 'icmp': 'ICMP para 1.1.1.1'}


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


def clock():
    now = dt.datetime.now(dt.timezone.utc)
    return {'brasilia': now.astimezone(BR).isoformat(timespec='milliseconds'),
            'utc': now.isoformat(timespec='milliseconds'), 'epoch_ms': int(now.timestamp()*1000)}


def human(c):
    return dt.datetime.fromisoformat(c['brasilia']).strftime('%d/%m/%Y às %H:%M:%S') + ' (Brasília, UTC-03:00)'


def letters(n):
    result = ''
    while n:
        n, r = divmod(n-1, 26)
        result = chr(65+r) + result
    return result


def letter_value(s):
    n = 0
    for c in s:
        n = n*26 + ord(c)-64
    return n


def reserve_folder(base):
    base.mkdir(parents=True, exist_ok=True)
    indices = [letter_value(p.name) for p in base.iterdir() if re.fullmatch('[A-Z]+', p.name)]
    n = max(indices, default=0)+1
    while True:
        folder = base / letters(n)
        try:
            folder.mkdir()
            return folder
        except FileExistsError:
            n += 1


def command(kind, marker):
    if kind == 'https':
        return ['env', 'LC_ALL=C', 'UWT_DEV_PASSTHROUGH=1', 'curl', '--disable',
                '--noproxy', '*', '--proxy', '', '--proto', '=https', '--connect-timeout', '15',
                '--max-time', '35', '--verbose', '--no-progress-meter', '--fail', URL]
    if kind == 'icmp':
        return ['env', 'LC_ALL=C', 'ping', '-4', '-n', '-c', '3', '-W', '2', '-w', '10', '-p', marker, TARGET]
    return ['env', 'LC_ALL=C', 'ip', '-4', 'route', 'get', TARGET]


def classify(kind, rc, stdout, stderr, stopped=None):
    if stopped:
        return 'INCONCLUSIVO', 'Comando interrompido ou encerrado pelo limite de tempo; consulte a saída.'
    if kind == 'contexto':
        return ('REGISTRADO', 'Rota exibida; esta consulta não envia um ping.') if rc == 0 else (
            'INCONCLUSIVO', 'Não foi possível consultar a rota; confira a saída.')
    if kind == 'https':
        if rc != 0:
            return 'INCONCLUSIVO', 'A requisição falhou. Erro de DNS, TLS ou conexão não comprova isolamento.'
        try:
            data = json.loads(stdout)
            if not isinstance(data, dict) or type(data.get('IsTor')) is not bool:
                raise ValueError('IsTor ausente ou inválido')
            ipaddress.ip_address(data['IP'])
        except (ValueError, KeyError, TypeError):
            return 'INCONCLUSIVO', 'A resposta não contém IsTor booleano e IP válidos; confira a saída original.'
        if data['IsTor']:
            return 'SAIDA_TOR', f"IsTor: true | IP de saída: {data['IP']}. Esta requisição saiu pela rede Tor."
        return 'ATENCAO_SAIDA_NAO_TOR', f"IsTor: false | IP: {data['IP']}. O serviço não reconheceu saída Tor; revise antes da coleta definitiva."
    text = stdout + '\n' + stderr
    counts = re.search(r'(\d+) packets transmitted,\s*(\d+) (?:packets )?received', text)
    if rc == 0 or (counts and int(counts[2]) > 0):
        return 'ATENCAO_ICMP_RESPONDEU', 'O ping obteve resposta externa. Resultado inesperado: revise a rede da VM.'
    lower = text.lower()
    if ('socket' in lower or 'cap_net_raw' in lower) and (
            'operation not permitted' in lower or 'permission denied' in lower or 'cap_net_raw' in lower):
        return 'PERMISSAO_SOCKET', 'O ping não conseguiu abrir o socket. Isso não demonstra bloqueio de pacotes na rede.'
    if counts and int(counts[1]) > 0 and int(counts[2]) == 0:
        return 'SEM_RESPOSTA_ICMP', 'Nenhuma resposta ICMP. Compatível com bloqueio; a falta de resposta sozinha não prova sua causa.'
    return 'INCONCLUSIVO', 'O ping terminou com erro de execução. Confira a mensagem; não classificar automaticamente como bloqueio.'


class Session:
    def __init__(self, folder, mode, tty):
        self.folder, self.tty = folder, tty
        self.prefix = 'cenario04-isolamento-' + ('teste-' if mode == 'teste' else '') + folder.name.lower()
        self.log = self.path('terminal.log').open('xb', buffering=0)
        self.data = {'script': VERSION, 'identificacao_script': dict(SCRIPT_IDENTITY), 'modo': mode, 'tentativa': folder.name,
                     'maquina': socket.gethostname(), 'inicio': clock(), 'fim': None,
                     'marcador_ping': secrets.token_hex(8), 'comandos': [], 'ocorrencias': [],
                     'relogio_host': 'não medido; horários registrados na Workstation'}
        self.save()

    def path(self, suffix):
        return self.folder / (self.prefix+'-'+suffix)

    def say(self, text=''):
        self.raw((text+'\n').encode('utf-8'))

    def raw(self, data):
        self.log.write(data)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    def ask(self, prompt):
        self.raw(prompt.encode('utf-8'))
        answer = self.tty.readline()
        if not answer:
            raise EOFError()
        # O eco do terminal já mostra a resposta; guardamos somente no arquivo.
        self.log.write(answer.encode('utf-8'))
        return answer.strip()

    def latest(self, kind):
        return next((r for r in reversed(self.data['comandos']) if r['tipo'] == kind), None)

    def filters(self):
        pattern = ':'.join(re.findall('..', self.data['marcador_ping']))
        return ['icmp or icmpv6', f'icmp && ip.addr == {TARGET}',
                f'icmp && ip.addr == {TARGET} && frame contains {pattern}']

    def summary(self):
        lines = ['============ RESUMO DO TESTE DE ISOLAMENTO ============',
                 f"Sessão: {self.prefix}", f"Início: {human(self.data['inicio'])}"]
        if self.data['fim']:
            lines.append('Fim: '+human(self.data['fim']))
        for kind, title in TITLES.items():
            runs = [r for r in self.data['comandos'] if r['tipo'] == kind]
            lines.append('\n'+title+':')
            if not runs:
                lines.append('  Ainda não executado.')
            for r in runs:
                lines.append(f"  Execução {r['numero']:02d}: {r['resultado']} | retorno {r['retorno']}")
                lines.append('  '+r['interpretacao'])
        lines += ['', LINE, 'FILTROS DE EXIBIÇÃO NO WIRESHARK DO HOST',
                  'Aplique um por vez; copie sem a numeração.', LINE]
        lines += [f'[ {n:02d} ] {f}' for n, f in enumerate(self.filters(), 1)]
        lines += [LINE, '01: visão geral. 02: ICMP envolvendo o destino do ping.',
                  '03: inclui o marcador desta tentativa para distinguir o teste.',
                  'Se o ping for bloqueado na VM, pode não aparecer na captura do host.',
                  'Zero pacotes, sozinho, não comprova isolamento.',
                  'O resultado HTTPS é lido no terminal: o conteúdo está cifrado na captura.',
                  '', 'As repetições e os resultados anteriores permanecem registrados.',
                  'Estes testes mostram o comportamento observado, não uma garantia universal.']
        if self.data['fim']:
            lines += ['', checksum_panel(self.data['identificacao_script'])]
        return '\n'.join(lines)

    def save(self):
        self.data['atualizado'] = clock()
        for suffix, text in [('resumo.json', json.dumps(self.data, ensure_ascii=False, indent=2)+'\n'),
                             ('resumo.txt', self.summary()+'\n')]:
            target = self.path(suffix)
            tmp = target.with_suffix(target.suffix+'.tmp')
            tmp.write_text(text, encoding='utf-8')
            tmp.replace(target)

    def run(self, kind, timeout=None):
        args = command(kind, self.data['marcador_ping'])
        number = len(self.data['comandos'])+1
        title = TITLES.get(kind, 'Rota da Workstation')
        self.say('\n'+'='*68)
        self.say(f'EXECUÇÃO {number:02d} | {title}')
        self.say(LINE)
        if kind == 'https':
            self.say('Objetivo: tentar HTTPS sem proxy explícito no aplicativo.')
            self.say('Esperado: resposta com IsTor: true, pelo encaminhamento do Whonix.')
        elif kind == 'icmp':
            self.say('Objetivo: tentar três pings externos, sem resolução DNS.')
            self.say('Esperado: nenhuma resposta externa; vamos distinguir erros de permissão.')
        self.say('\nComando:')
        self.say('$ '+shlex.join(args))
        started = clock()
        self.say('\nInício: '+human(started))
        self.say(LINE+'\nSAÍDA ORIGINAL DO COMANDO\n'+LINE)
        row = {'numero': number, 'tipo': kind, 'sudo': False, 'comando': args,
               'inicio': started, 'fim': None, 'retorno': None, 'resultado': 'EM_EXECUCAO',
               'interpretacao': 'Execução em andamento.', 'stdout': '', 'stderr': ''}
        self.data['comandos'].append(row)
        self.save()
        chunks = {'stdout': [], 'stderr': []}
        stopped = None
        proc = None
        deadline = time.monotonic() + (timeout if timeout is not None else (45 if kind=='https' else 15))
        try:
            proc = subprocess.Popen(args, stdin=self.tty, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with selectors.DefaultSelector() as sel:
                sel.register(proc.stdout, selectors.EVENT_READ, 'stdout')
                sel.register(proc.stderr, selectors.EVENT_READ, 'stderr')
                while sel.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    for key, _ in sel.select(0.15):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if chunk:
                            chunks[key.data].append(chunk)
                            self.raw(chunk)
                        else:
                            sel.unregister(key.fileobj)
                rc = proc.wait(timeout=max(0.1, deadline-time.monotonic()))
        except (KeyboardInterrupt, TimeoutError, subprocess.TimeoutExpired) as exc:
            stopped = 'interrompido' if isinstance(exc, KeyboardInterrupt) else 'limite_de_tempo'
            if proc:
                proc.terminate()
                try:
                    out, err = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, err = proc.communicate(timeout=2)
                for key, chunk in [('stdout', out), ('stderr', err)]:
                    if chunk:
                        chunks[key].append(chunk)
                        self.raw(chunk)
            rc = proc.returncode if proc else None
        except OSError as exc:
            rc = 127
            chunk = (str(exc)+'\n').encode('utf-8')
            chunks['stderr'].append(chunk)
            self.raw(chunk)
        finally:
            if proc:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
                proc.stdout.close()
                proc.stderr.close()
        row.update(fim=clock(), retorno=rc, interrupcao=stopped,
                   stdout=b''.join(chunks['stdout']).decode('utf-8', errors='replace'),
                   stderr=b''.join(chunks['stderr']).decode('utf-8', errors='replace'))
        row['resultado'], row['interpretacao'] = classify(kind, rc, row['stdout'], row['stderr'], stopped)
        self.say('\n'+LINE+'\nFIM DA SAÍDA ORIGINAL\n'+LINE)
        self.say('Fim: '+human(row['fim']))
        self.say(f'Código de retorno: {rc}')
        self.say('>>> '+row['resultado'])
        self.say('>>> '+row['interpretacao'])
        if row['resultado'] == 'PERMISSAO_SOCKET':
            self.say('>>> Restrição local registrada. Você pode consultar o resumo ou finalizar.')
        self.save()

    def menu(self):
        self.say('\n============ TESTE DE ISOLAMENTO | WORKSTATION ============')
        self.say('Sessão: '+self.prefix)
        self.say('Data e horário: '+human(clock()))
        self.say(LINE)
        pending = [k for k in TITLES if not self.latest(k)]
        for n, (kind, title) in enumerate(TITLES.items(), 1):
            row = self.latest(kind)
            tag = ' [PRÓXIMO]' if pending and pending[0] == kind else ''
            self.say(f'[ {n} ] {title}'+tag)
            if row:
                self.say('      Último resultado: '+row['resultado']+' (selecionar novamente repete)')
        self.say(LINE)
        self.say('[ S ] Resumo e filtros   [ O ] Anotar ocorrência   [ F ] Finalizar')
        self.say('Escolha uma etapa. O comando e sua saída aparecerão antes da interpretação.')
        self.say(LINE)


def main():
    parser = argparse.ArgumentParser(description='Cenário 4: HTTPS e ICMP na Whonix-Workstation.')
    parser.add_argument('--ajuda', action='help')
    parser.add_argument('--pasta', default='/media/sf_cenario04', help='pasta compartilhada já montada')
    parser.add_argument('--modo', choices=['teste', 'coleta'], default='teste', help='padrão do menu de modo')
    parser.add_argument('--verificar', action='store_true', help='conferir ferramentas e escrita; não acessa a rede')
    args = parser.parse_args()
    root = Path(args.pasta).expanduser().resolve()
    if not root.is_dir():
        raise RuntimeError('Pasta compartilhada não encontrada: '+str(root))
    missing = [name for name in ('curl', 'ping', 'ip', 'env') if not shutil.which(name)]
    if missing:
        raise RuntimeError('Ferramentas não encontradas: '+', '.join(missing))
    if args.verificar:
        probe = root / ('.verificar-isolamento-'+secrets.token_hex(8))
        try:
            with probe.open('x', encoding='utf-8') as f:
                f.write('verificação de escrita\n')
        finally:
            probe.unlink(missing_ok=True)
        print('OK: ferramentas disponíveis e pasta gravável. Nenhum teste de rede executado.')
        print('Execute o ensaio na Workstation, com o Gateway ligado.')
        return 0
    session = None
    with open('/dev/tty', 'r', encoding='utf-8') as tty:
        def ask(prompt):
            print(prompt, end='', flush=True)
            line = tty.readline()
            if not line:
                raise EOFError()
            return line.strip()
        print('\nCENÁRIO 4 | TESTE DE ISOLAMENTO DA WORKSTATION')
        print('Máquina:', socket.gethostname())
        print('Execute na Workstation. Mantenha o Gateway ligado e conectado ao Tor.')
        print('\n[ 1 ] Ensaio/teste\n[ 2 ] Coleta definitiva')
        default = '1' if args.modo == 'teste' else '2'
        while True:
            mode = {'1': 'teste', '2': 'coleta'}.get(ask(f'Escolha o modo [{default}]: ') or default)
            if mode:
                break
            print('Digite 1 ou 2.')
        base = root/'Registros'/'Workstation'/('Testes' if mode=='teste' else 'Coletas')
        folder = reserve_folder(base)
        try:
            session = Session(folder, mode, tty)
            session.say('\nPasta desta tentativa: '+str(folder))
            session.say('As letras da Workstation são independentes das letras do monitor do Gateway.')
            session.ask('Inicie a captura no Wireshark do host. Pressione Enter para começar: ')
            session.run('contexto')
            while True:
                session.menu()
                choice = session.ask('Opção: ').upper()
                if choice in ('1', '2'):
                    kind = 'https' if choice=='1' else 'icmp'
                    if kind == 'icmp' and not session.latest('https'):
                        if session.ask('HTTPS ainda não foi testado. Executar ICMP primeiro? [s/N]: ').lower() != 's':
                            continue
                    session.run(kind)
                elif choice == 'S':
                    session.say('\n'+session.summary())
                elif choice == 'O':
                    note = session.ask('Descreva a ocorrência: ')
                    if note:
                        session.data['ocorrencias'].append({'horario': clock(), 'texto': note})
                        session.save()
                        session.say('>>> Ocorrência registrada.')
                elif choice == 'F':
                    break
                else:
                    session.say('Opção não disponível. Escolha uma das opções exibidas.')
        except (KeyboardInterrupt, EOFError):
            if session:
                session.say('\n>>> Encerramento solicitado pelo terminal.')
        finally:
            if session:
                try:
                    session.data['fim'] = clock()
                    session.data['identificacao_script'] = final_script_identity()
                    session.save()
                    session.say('\n'+session.summary())
                    session.say('\nRegistros salvos em: '+str(folder))
                    session.say('Encerre e salve a captura do Wireshark com a mesma identificação desta tentativa.')
                finally:
                    session.log.close()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as exc:
        print('\nERRO: '+str(exc), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('\nEncerrado antes de iniciar o ensaio.')
        sys.exit(130)
PYTHON_ISOLAMENTO
