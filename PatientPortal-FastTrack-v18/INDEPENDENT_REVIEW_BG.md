# Задание за независим преглед преди реална употреба

**Обект: интернет Patient Portal; версия 18; HOLD / NO-GO.**

## Материали за проверяващия

Предоставят се source release и SHA256 manifest, TEST_REPORT_BG.md, WINDOWS_ACCEPTANCE_BG.md, INTERNET_DEPLOYMENT_BG.md и съответните sanitized reports. Локалният Windows backup е създаден успешно според screenshot6 files; потребителят съобщи „работи“ след restore/drill процедурата. Това не е независим restore audit или заснет HTTP trace. Не се предоставят реални пациентски файлове, генерираните пароли, DB, `.env`, keys или backup архиви в публичния repository.

## Конкретни въпроси и очакван резултат

| Област | Какво трябва да се установи | Очаквано доказателство |
| --- | --- | --- |
| Bootstrap/schema | Всички AV/legacy/admission/freshness защити се включват и в предложения production вход; няма import-time DDL/demo seeds/bypass | Преглед на новия bootstrap/schema diff и target startup/refusal тестове |
| Интернет граница | HTTPS hostname/cert, Secure cookies, точен trusted proxy, body/rate/time/connection лимити, вътрешни app/clamd ports | Конфигурации с прикрити secrets и външни HTTPS/host/header тестове |
| Авторизация | Staff MFA/role/CSRF, owner200/other404, непубликувани/legacy/failed-scan PDF hold | Synthetic acceptance от избрания staging server, включително директни URL |
| Операции и възстановяване | Signature update/freshness/outage, спиране/рестарт, ресурси/диск/наблюдение, отделен backup/key custody/restore | Target logs/санитизирани flags, измерени граници и timed recovery с определени отговорници |
| Данни и правно основание | Hosting/backup договори, достъпи, identity handoff, retention, incident handling, GDPR/DPIA screening | Подписан преглед от компетентните отговорници с изрично описани ограничения |

Оценката трябва да различава автоматични synthetic tests, потребителски съобщения, реални target измервания и независими заключения. Успешно локално изпълнение не се пренася автоматично към Интернет/VPS/друг storage или операционна система. Не е допустимо заобикаляне на gate/AV/TLS, за да се получи зелен резултат.

## Документ за решение

Нужни са идентификатор и SHA256 на конкретния release; описана target среда и конфигурация без secrets; проверяващ/роля/дата; намерени проблеми с риск и условие за отстраняване; доказателства/ограничения; изрично решение за конкретното внедряване. Незапълнен шаблон, автоматичен PASS или собствена оценка на разработчика не са независимо одобрение.

HOLD / NO-GO остава, докато такова решение и отделното операторско одобрение за реалното внедряване не са налични. Този файл не дава одобрение и не променя статуса. Real-data migration, services, ACL, DNS/firewall или друга инсталация не се изпълняват от версия 18.
