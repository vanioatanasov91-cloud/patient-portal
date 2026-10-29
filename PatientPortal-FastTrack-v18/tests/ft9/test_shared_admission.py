"""Actual independent spawned processes contend on one generated lock pool."""
from pathlib import Path
import multiprocessing as mp
import os
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'app'))
from shared_pdf_admission import DiskSlotPool, AdmissionUnavailable


def contender(folder, start, release, results):
    pool = DiskSlotPool(Path(folder), 2)
    start.wait(timeout=15)
    lease = pool.try_acquire()
    results.put(lease is not None)
    if lease:
        try: release.wait(timeout=20)
        finally: lease.close()


def crash_holder(folder, ready):
    pool = DiskSlotPool(Path(folder), 2)
    a, b = pool.try_acquire(), pool.try_acquire()
    ready.put(bool(a and b))
    # Deliberately bypass cleanup; the OS must reclaim the file locks.
    ready.close(); ready.join_thread()
    os._exit(0)


def main():
    checks = 0
    def check(ok, label):
        nonlocal checks
        assert ok, label
        checks += 1
        print('PASS: ' + label, flush=True)
    ctx = mp.get_context('spawn')
    with tempfile.TemporaryDirectory(prefix='FT9_SYNTHETIC_LOCKS_') as tmp:
        folder = Path(tmp) / 'total'
        pool = DiskSlotPool.prepare(folder, 2)
        start, release, results = ctx.Barrier(8), ctx.Event(), ctx.Queue()
        workers = [ctx.Process(target=contender, args=(folder,start,release,results)) for _ in range(8)]
        try:
            for worker in workers: worker.start()
            admitted = [results.get(timeout=20) for _ in workers]
            check(sum(admitted) == 2, 'eight independent processes admit exactly two operations in aggregate')
            check(pool.try_acquire() is None, 'parent cannot bypass occupied child-process slots')
        finally:
            release.set()
            for worker in workers:
                worker.join(timeout=10)
                if worker.is_alive(): worker.terminate(); worker.join(timeout=5)
            results.close(); results.join_thread()
        check(all(w.exitcode == 0 for w in workers), 'all contender processes exited normally')
        a, b = pool.try_acquire(), pool.try_acquire()
        check(a is not None and b is not None and pool.try_acquire() is None, 'all successful response slots recover')
        a.close(); a.close(); b.close()
        ready = ctx.Queue()
        child = ctx.Process(target=crash_holder, args=(folder,ready))
        child.start()
        try:
            check(ready.get(timeout=15), 'crash fixture held both shared slots')
            child.join(timeout=10)
            check(child.exitcode == 0, 'crash fixture exited without explicit lease release')
            a, b = pool.try_acquire(), pool.try_acquire()
            check(a is not None and b is not None, 'OS reclaims locks after abrupt process exit without a lease TTL')
            a.close(); b.close()
        finally:
            if child.is_alive(): child.terminate(); child.join(timeout=5)
            ready.close(); ready.join_thread()
        try: DiskSlotPool(folder, 3)
        except AdmissionUnavailable: check(True, 'inconsistent worker capacity fails closed')
        else: raise AssertionError('mismatched capacity accepted')
        a = pool.try_acquire()
        (folder / 'slot-1').unlink()
        try: pool.try_acquire()
        except AdmissionUnavailable: check(True, 'missing shared state fails closed and is not recreated')
        else: raise AssertionError('missing slot accepted')
        finally: a.close()
        check(not (folder / 'slot-1').exists(), 'requests never replace lock files')
    print(f'PASS: FT9 SHARED ADMISSION ({checks} checks). HOLD / NO-GO.')


if __name__ == '__main__': main()
