"""Explicit foreground synthetic pilot CLI. Linux managed Docker only."""
import argparse
import json
import signal
import sys

from pilot_runtime import PilotError, initialize_pilot, refresh, serve, serve_http, status


def main():
    parser = argparse.ArgumentParser(description='Изолиран synthetic пилот; HOLD / NO-GO')
    subs = parser.add_subparsers(dest='command', required=True)
    init = subs.add_parser('init', help='Нов private pilot store и verified FreshClam snapshot')
    init.add_argument('--pilot-dir', required=True)
    init.add_argument('--confirm-isolated-synthetic-pilot', action='store_true', required=True)
    init.add_argument('--http-port', type=int, default=18080)
    init.add_argument('--scanner-port', type=int, default=13310)
    for name in ('serve', 'status', 'refresh', '_http'):
        command = subs.add_parser(name)
        command.add_argument('--pilot-dir', required=True)
        if name == 'refresh':
            command.add_argument('--confirm-offline-synthetic-pilot', action='store_true', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'init':
            root = initialize_pilot(args.pilot_dir, http_port=args.http_port, scanner_port=args.scanner_port)
            print('Подготвен е synthetic пилот: ' + str(root) + '. HOLD / NO-GO.')
        elif args.command == 'refresh':
            refresh(args.pilot_dir)
            print('Новият verified snapshot е избран offline. Повторете serve/preflight. HOLD / NO-GO.')
        elif args.command == 'status':
            result = status(args.pilot_dir)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['ready'] else 1
        elif args.command == '_http':
            serve_http(args.pilot_dir)
        else:
            def stop(signum, frame):
                raise KeyboardInterrupt()
            signal.signal(signal.SIGTERM, stop)
            serve(args.pilot_dir)
        return 0
    except KeyboardInterrupt:
        print('Собственият пилот е спрян. Данните са запазени. HOLD / NO-GO.')
        return 0
    except PilotError as exc:
        print('HOLD: ' + str(exc) + '. Вижте PILOT_BG.md.', file=sys.stderr)
        return 1
    except Exception as exc:
        # No credentials, SQL, raw scanner/proxy output or patient metadata.
        print('HOLD: пилотът не е готов (' + type(exc).__name__ + '). Вижте PILOT_BG.md.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
