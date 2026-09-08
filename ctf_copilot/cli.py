from __future__ import annotations

import argparse
import datetime
import json
from collections import Counter
from pathlib import Path

from .commands_text import COMMANDS
from .core import caesar, decode, recursive, resolve, scan, nmap, strings, xor_candidates
from .solve import solve as solve_target
from .tooling import binary_triage, forensic_triage, run_tool, summarize_tools, which
from .web import analyze as web_analyze, fetch as web_fetch, jwt as web_jwt, render as web_render
from .webtest import run_tests as web_run_tests


MORSE = {
    '.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I',
    '.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z'
}


def _print_lines(rows):
    for row in rows:
        print(row)


def _crypto_analyze(value: str) -> None:
    rows = recursive(value)
    if not rows:
        print('No obvious supported encoding chain detected.')
        return
    for depth, kind, text in rows:
        print(f'{depth}. {kind}: {text}')


def _crypto_decode(value: str, kind: str) -> None:
    if kind == 'auto':
        rows = recursive(value)
        if rows:
            for depth, name, text in rows:
                print(f'{depth}. {name}: {text}')
        else:
            print('No obvious supported encoding detected.')
    elif kind == 'caesar':
        for shift, text in caesar(value):
            print(f'{shift:2}: {text}')
    else:
        print(decode(kind, value))


def _forensics_metadata(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('exiftool'):
        raise SystemExit('exiftool is not installed.')
    _, out = run_tool(['exiftool', str(p)], timeout=30, max_output=80_000)
    print(out or '(no metadata output)')


def _forensics_strings(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if which('strings'):
        _, out = run_tool(['strings', '-a', '-n', '4', str(p)], timeout=30, max_output=120_000)
        print(out or '(no printable strings)')
    else:
        data = p.read_bytes()[:8_000_000]
        _print_lines(strings(data))


def _forensics_hex(path: str, count: int) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    with p.open('rb') as fh:
        print(fh.read(count).hex(' '))


def _reverse_strings(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('strings'):
        raise SystemExit('strings is not installed.')
    _, out = run_tool(['strings', '-a', '-n', '4', str(p)], timeout=30, max_output=120_000)
    keywords = ('flag','password','correct','wrong','secret','admin','success','fail','key')
    hits = [line for line in out.splitlines() if any(k in line.lower() for k in keywords)]
    _print_lines(hits or ['No obvious high-signal strings found.'])


def _reverse_disasm(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('objdump'):
        raise SystemExit('objdump is not installed.')
    _, out = run_tool(['objdump', '-d', str(p)], timeout=45, max_output=120_000)
    print(out or '(no disassembly output)')


def _pwn_checksec(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('checksec'):
        raise SystemExit('checksec is not installed.')
    _, out = run_tool(['checksec', '--file=' + str(p)], timeout=30, max_output=40_000)
    print(out or '(no checksec output)')


def _pwn_rop(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('ROPgadget'):
        raise SystemExit('ROPgadget is not installed.')
    _, out = run_tool(['ROPgadget', '--binary', str(p), '--only', 'pop|ret|leave'], timeout=45, max_output=80_000)
    print(out or '(no matching gadgets found)')


def _network_scan(host: str, ports: str | None, timeout: float) -> None:
    ips = resolve(host)
    if not ips:
        raise SystemExit('Could not resolve target.')
    plist = [int(x.strip()) for x in ports.split(',')] if ports else None
    rows = scan(ips[0], plist, timeout)
    if not rows:
        print('No tested TCP ports were open.')
        return
    for port, service in rows:
        print(f'{port}/tcp OPEN {service}')


def _osint_domain(domain: str) -> None:
    print(f'Domain: {domain}')
    try:
        ips = resolve(domain)
        print('Resolved IPs:')
        _print_lines([f'  {ip}' for ip in ips])
    except Exception as exc:
        print(f'Resolution failed: {exc}')
    if which('whois'):
        _, out = run_tool(['whois', domain], timeout=30, max_output=50_000)
        if out:
            print('\nWHOIS:')
            print(out)
    else:
        print('\nWHOIS tool not installed; DNS resolution only.')


def _osint_username(username: str) -> None:
    # Offline lead generation only; it does not claim the profiles exist.
    sites = [
        ('GitHub', f'https://github.com/{username}'),
        ('GitLab', f'https://gitlab.com/{username}'),
        ('Reddit', f'https://www.reddit.com/user/{username}'),
    ]
    print(f'Username leads for: {username}')
    print('These are search leads, not confirmed accounts:')
    for name, url in sites:
        print(f'  {name:<8} {url}')


def _web_endpoints(url: str) -> None:
    info = web_analyze(url)
    rows = info['endpoints'] + [ep for eps in info['script_endpoints'].values() for ep in eps]
    _print_lines(list(dict.fromkeys(rows)) or ['No endpoint-like paths found.'])


def _web_test(args) -> None:
    if not args.confirm_authorized:
        raise SystemExit(
            'Refusing active probes without --confirm-authorized. '
            'Use only on CTF targets or systems you are authorized to test.'
        )
    print(web_run_tests(args.url, args.headers, args.methods, args.xss, args.sqli))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='ctf',
        description='CTF Copilot v0.5 - one clear command group per CTF category',
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    q = sub.add_parser('solve', help="First command when you don't know where to start")
    q.add_argument('target', help='File, URL, or text')
    q.set_defaults(fn=lambda a: print(solve_target(a.target)))

    q = sub.add_parser('web', help='Web exploitation helpers')
    web = q.add_subparsers(dest='action', required=True)
    z = web.add_parser('analyze', help='Inspect page, forms, scripts, cookies, endpoints')
    z.add_argument('url'); z.set_defaults(fn=lambda a: print(web_render(web_analyze(a.url))))
    z = web.add_parser('test', help='Controlled active probes on an authorized target')
    z.add_argument('url'); z.add_argument('--confirm-authorized', action='store_true')
    z.add_argument('--headers', action='store_true'); z.add_argument('--methods', action='store_true')
    z.add_argument('--xss', action='store_true'); z.add_argument('--sqli', action='store_true')
    z.set_defaults(fn=_web_test)
    z = web.add_parser('endpoints', help='Extract endpoint-like paths from HTML/JS')
    z.add_argument('url'); z.set_defaults(fn=lambda a: _web_endpoints(a.url))
    z = web.add_parser('headers', help='Show response headers')
    z.add_argument('url'); z.set_defaults(fn=lambda a: _print_lines(f'{k}: {v}' for k, v in web_fetch(a.url)[2].items()))
    z = web.add_parser('jwt', help='Decode JWT header and payload')
    z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(web_jwt(a.token), indent=2) if web_jwt(a.token) else 'Not a decodable JWT-like token.'))
    z = web.add_parser('compare', help='Compare status and body size for two URLs')
    z.add_argument('url1'); z.add_argument('url2')
    z.set_defaults(fn=lambda a: print(f"A: status={web_fetch(a.url1)[0]} size={len(web_fetch(a.url1)[3])}\nB: status={web_fetch(a.url2)[0]} size={len(web_fetch(a.url2)[3])}"))

    q = sub.add_parser('crypto', help='Cryptography and encoding helpers')
    crypto = q.add_subparsers(dest='action', required=True)
    z = crypto.add_parser('analyze', help='Detect and follow likely encoding layers')
    z.add_argument('value'); z.set_defaults(fn=lambda a: _crypto_analyze(a.value))
    z = crypto.add_parser('decode', help='Decode text; defaults to automatic recursive decoding')
    z.add_argument('value'); z.add_argument('--kind', default='auto', choices=['auto','base64','base32','hex','ascii','binary','url','rot13','atbash','caesar'])
    z.set_defaults(fn=lambda a: _crypto_decode(a.value, a.kind))
    z = crypto.add_parser('xor', help='Try single-byte XOR candidates from hex input')
    z.add_argument('value'); z.set_defaults(fn=lambda a: _print_lines(f'key=0x{k:02x} score={score:.3f} text={text[:120]}' for score, k, text in xor_candidates(a.value)))
    z = crypto.add_parser('frequency', help='Character-frequency analysis')
    z.add_argument('value'); z.set_defaults(fn=lambda a: _print_lines(f'{repr(ch)} {count}' for ch, count in Counter(a.value).most_common()))

    q = sub.add_parser('forensics', help='Forensics triage and inspection')
    forensic = q.add_subparsers(dest='action', required=True)
    z = forensic.add_parser('triage', help='file + metadata + binwalk + interesting strings')
    z.add_argument('path'); z.set_defaults(fn=lambda a: print(forensic_triage(a.path)))
    z = forensic.add_parser('metadata', help='Show metadata with ExifTool')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _forensics_metadata(a.path))
    z = forensic.add_parser('strings', help='Extract printable strings')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _forensics_strings(a.path))
    z = forensic.add_parser('hex', help='Show beginning of file as hex')
    z.add_argument('path'); z.add_argument('--bytes', type=int, default=256)
    z.set_defaults(fn=lambda a: _forensics_hex(a.path, max(1, min(a.bytes, 4096))))

    q = sub.add_parser('reverse', help='Reverse-engineering helpers')
    reverse = q.add_subparsers(dest='action', required=True)
    z = reverse.add_parser('triage', help='Binary first pass: file/checksec/readelf/strings/ROP preview')
    z.add_argument('path'); z.set_defaults(fn=lambda a: print(binary_triage(a.path)))
    z = reverse.add_parser('strings', help='Show high-signal reversing strings')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _reverse_strings(a.path))
    z = reverse.add_parser('disasm', help='Disassemble with objdump')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _reverse_disasm(a.path))

    q = sub.add_parser('pwn', help='Binary-exploitation helpers')
    pwn = q.add_subparsers(dest='action', required=True)
    z = pwn.add_parser('triage', help='Binary/pwn first pass')
    z.add_argument('path'); z.set_defaults(fn=lambda a: print(binary_triage(a.path)))
    z = pwn.add_parser('checksec', help='Show NX/PIE/Canary/RELRO')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _pwn_checksec(a.path))
    z = pwn.add_parser('rop', help='Preview useful ROP gadgets')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _pwn_rop(a.path))

    q = sub.add_parser('network', help='Network and recon helpers')
    network = q.add_subparsers(dest='action', required=True)
    z = network.add_parser('resolve', help='Resolve a host/domain to IP addresses')
    z.add_argument('host'); z.set_defaults(fn=lambda a: _print_lines(resolve(a.host)))
    z = network.add_parser('scan', help='Check common or supplied TCP ports')
    z.add_argument('host'); z.add_argument('--ports'); z.add_argument('--timeout', type=float, default=.4)
    z.set_defaults(fn=lambda a: _network_scan(a.host, a.ports, a.timeout))
    z = network.add_parser('services', help='Nmap service/version detection')
    z.add_argument('host'); z.set_defaults(fn=lambda a: print(nmap(a.host) or 'nmap not installed or no output.'))

    q = sub.add_parser('osint', help='Passive OSINT helpers')
    osint = q.add_subparsers(dest='action', required=True)
    z = osint.add_parser('domain', help='Passive domain resolution and WHOIS when available')
    z.add_argument('domain'); z.set_defaults(fn=lambda a: _osint_domain(a.domain))
    z = osint.add_parser('username', help='Generate common username profile leads')
    z.add_argument('username'); z.set_defaults(fn=lambda a: _osint_username(a.username))

    q = sub.add_parser('misc', help='Miscellaneous CTF helpers')
    misc = q.add_subparsers(dest='action', required=True)
    z = misc.add_parser('morse', help='Decode Morse')
    z.add_argument('value'); z.set_defaults(fn=lambda a: print(' '.join(''.join(MORSE.get(x, '?') for x in word.split()) for word in a.value.split(' / '))))
    z = misc.add_parser('base', help='Convert between bases 2/8/10/16')
    z.add_argument('value'); z.add_argument('--from-base', type=int, choices=[2,8,10,16], required=True); z.add_argument('--to-base', type=int, choices=[2,8,10,16], required=True)
    z.set_defaults(fn=lambda a: print(format(int(a.value, a.from_base), {2:'b',8:'o',10:'d',16:'x'}[a.to_base])))
    z = misc.add_parser('timestamp', help='Convert Unix timestamp to local ISO time')
    z.add_argument('value'); z.set_defaults(fn=lambda a: print(datetime.datetime.fromtimestamp(float(a.value)).astimezone().isoformat()))

    q = sub.add_parser('tools', help='Audit useful Kali/CTF tools installed on this machine')
    q.set_defaults(fn=lambda a: print(summarize_tools()))

    q = sub.add_parser('commands', help='Show the compact categorized command reference')
    q.set_defaults(fn=lambda a: print(COMMANDS))

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
