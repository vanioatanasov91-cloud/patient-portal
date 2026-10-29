# Patient Portal — Fast Track18

Работно име **„Анакиевски“**, бъдещ достъп през интернет от вкъщи. Домейн/сървър още няма. Предложение: **anakievski.bg → portal.anakievski.bg**, след проверка на регистрационната наличност/права. Публичният DNS не намери NS делегация за предложените имена, но това не доказва свобода за регистрация; registry страницата върна HTTP503 при опита.

**[Изтегли версия18](downloads/PatientPortal_FastTrack_v18_Codex.zip)**. Пакетът съдържа текущия код, точния Windows PDF/backup/restore acceptance запис и конкретен план за Интернет внедряване. За разглеждане на плана не е нужно да спираш/преинсталираш работещия портал.

- [Домейн и hosting](PatientPortal-FastTrack-v18/DOMAIN_AND_HOSTING_BG.md)
- [Архитектура и5 етапа](PatientPortal-FastTrack-v18/INTERNET_DEPLOYMENT_BG.md)
- [Задание за независим преглед](PatientPortal-FastTrack-v18/INDEPENDENT_REVIEW_BG.md)
- [Действителен отчет](PatientPortal-FastTrack-v18/TEST_REPORT_BG.md)

**18/18 regression групи PASS**. Runtime app/scanner/backup/desktop кодът и старите тестове са запазени от17. Променени са deployment документите/evidence и UI/runner version labels. Кандидатът остава localhost/synthetic; нужен е отделен прегледан production bootstrap/schema path, който запазва AV/legacy hold/shared admission/freshness и HTTPS/MFA договора.

Пакет: 360145 bytes,141 source/report файла. SHA256: `5600c773d00cb78614e3400e00bf494ea7d11279f4ed198dccf0276952989332`. Няма пароли, DB/PDF, keys,.ppbk, venv или ClamAV runtime. Старите releases и ZIP са запазени. Няма покупка на домейн/hosting, публично внедряване или DNS/firewall/service/ACL промени. **HOLD / NO-GO остава до независимо одобрение за конкретната реална среда.**
