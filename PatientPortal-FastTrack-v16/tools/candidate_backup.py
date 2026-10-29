"""Operator CLI for offline synthetic candidate backup/restore; no secret argv."""
import argparse
import getpass
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
# Avoid collision with this CLI filename when importing the app module.
import candidate_backup as backup


def main():
    parser=argparse.ArgumentParser(description='Offline encrypted synthetic candidate backup; HOLD / NO-GO')
    subs=parser.add_subparsers(dest='command',required=True)
    create=subs.add_parser('create')
    create.add_argument('--data-dir',required=True)
    create.add_argument('--output',required=True)
    create.add_argument('--confirm-offline-synthetic-store',action='store_true',required=True)
    restore=subs.add_parser('restore')
    restore.add_argument('--file',required=True)
    restore.add_argument('--destination',required=True)
    restore.add_argument('--confirm-synthetic-restore',action='store_true',required=True)
    args=parser.parse_args()
    key=getpass.getpass('BACKUP PASSPHRASE (16+ chars, never shared): ')
    try:
        if args.command=='create':
            if key!=getpass.getpass('Repeat backup passphrase: '):raise ValueError('confirmation mismatch')
            count=backup.create(args.data_dir,args.output,key)
        else:count=backup.restore(args.file,args.destination,key)
        print('Успешна offline synthetic операция: '+str(count)+' файла. HOLD / NO-GO.')
        return 0
    except Exception as exc:
        print('HOLD: backup/restore отказан ('+type(exc).__name__+'); live stores/overwrite/невалидни архиви не са разрешени.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
