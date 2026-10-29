# Продължение след Fast Track 14

Прочети AGENTS.md, README_BG.md, PILOT_BG.md, PILOT_REPORT_BG.md, TEST_REPORT_BG.md, CANDIDATE_START_BG.md и NEXT_SPRINT_BG.md. Има normal persistent-data foreground Linux/UID1000 pilot CLI init/serve/status/offline refresh. Няма Windows/public/OS service deployment. Network промяната вече е приложена; не я искай отново.

Пилотните данни са извън source, в отделна private папка. Не ги слагай в ZIP/chat. Не повтаряй init върху работещ store, не мигрирай real DB, не подменяй locks/CVD snapshot при живи workers. Refresh изисква offline lifecycle guard и поне1h между official updates. Per-request scanner VERSION/48h precheck се включва само от explicit pilot entrypoint; normal candidate/legacy behavior е запазено.

Всичките18 regression групи остават. Group12 запазва original preflight/updater tests; group17 първо изпълнява original42 candidate workflow assertions без редакции, после8 pilot guard/HTTP restart test cases. Default suite не използва реален Docker/download.

```bash
python -B tools/fasttrack_runner.py --include-synthetic
```

Real pilot acceptance е отделна явна команда от PILOT_BG.md само върху unused marked synthetic pilot. Не я повтаряй върху вече използвания store; няма автоматично reset/reseed. След успешно acceptance остави нормалния serve за локално ръчно използване само докато средата е активна. Cloud localhost не е browser preview URL.

Следва независим reviewer и отделна целева deployment/access процедура, ако се иска достъп от друга машина. Не подписвай сам независим review и не премахвай HOLD / NO-GO. Не добавяй нови тестови групи само за версията. Diff → manifests → all regression groups → actual reports → source ZIP без keys/accounts/DB/PDF/archives.
