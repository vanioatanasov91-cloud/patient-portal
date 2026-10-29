# Продължение след Fast Track 15

Прочети AGENTS.md, README_BG.md, WINDOWS_START_BG.md, TEST_REPORT_BG.md, CANDIDATE_START_BG.md и NEXT_SPRINT_BG.md. Потребителят е на Windows10/11 с Python3.13 и default3.15. Не го карай отново да инсталира3.12 или да изпълнява setup от system32. START_WINDOWS.cmd избира3.13, извиква абсолютния source path и ползва собствен LOCALAPPDATA root. Не публикувай runtime credentials/DB/PDF.

Нова desktop schema1 е отделна от candidate schema2. Няма v14 adoption/migration/reset/reseed. Source integrity, explicit native exits, fixed dependency versions, singleton lifecycle и browser-after-HTTP readiness са включени. Няма auto Python/ClamAV/service/OS policy installation. --require-fresh-scanner се използва за desktop; normal legacy/candidate default behavior е запазено.

18 regression групи се запазват. Group17 верижно изпълнява original42 candidate,8 pilot,9 desktop cases; старите test source са непроменени. Default suite не инсталира/сваля пакети и не отваря native browser. Pip Windows64/CPython3.13 dry-run е отделно evidence, не native Windows approval.

```bash
python -B tools/fasttrack_runner.py --include-synthetic
```

След working Windows login следват synthetic center branding и отделно local scanner provisioning/preflight. Не конфигурирай Windows services/HTTPS/firewall/ACL/BitLocker или real DB без конкретна отделна operator процедура. Не премахвай HOLD / NO-GO; няма независимо одобрение.

Доставяй нова версия/source ZIP през проверен GitHub download URL. Вътрешни /workspace или sandbox линкове не се изтеглят от този интерфейс. Преди publish: diff,source manifests,all checks,actual evidence,ZIP без secrets/runtime,GitHub anonymous download/hash verification. Не прави нови test groups само за версията.
