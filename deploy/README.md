# Развёртывание Hermes Multica Bridge 0.6.0

Эта инструкция описывает настройку после копирования публичного пакета на целевой хост. Она не выполняет deployment автоматически.

## Выбор режима

### Standard

Standard не требует отдельного systemd sender.

1. Установить plugin directory в активный Hermes profile.
2. Открыть native Desktop **Multica Bridge → Реестр**.
3. Создать Connection, Workspace и Route.
4. Оставить Connection/Route выключенными до завершения настройки.
5. Для выбранного Standard Route ввести его write-only webhook/HMAC/PAT через route credential editor.
6. Проверить per-route readiness.
7. Включить Connection и Route только после проверки endpoint/Autopilot/trigger и source policy.

Один Hermes profile может содержать несколько независимых Connections/Workspaces/Routes. У каждого Standard Route отдельный credential namespace; UI показывает только presence и никогда не раскрывает сохранённое значение.

### Isolated

Isolated хранит Multica secrets вне plugin process и требует root/systemd настройки.
Для Isolated требуется Linux 6.5+ с `SO_PEERPIDFD` и unified cgroup v2; cgroup v1/hybrid не поддерживается и будет отклонён fail closed. На старом ядре sender откажет до чтения IPC-запроса.

Isolated Route использует отдельную template instance на каждый Route:

```text
hermes-multica-bridge@<instance>.socket
hermes-multica-bridge@<instance>.service
```

Instance ID выводится из UUIDv7 Route как `r-<route-id-без-дефисов>` и показывается Desktop в route-specific instructions.

## Файлы Isolated instance

Ожидаемая структура:

```text
/opt/hermes-multica-bridge/
/etc/hermes-multica-bridge/<instance>.toml
/etc/hermes-multica-bridge/credentials/<instance>/webhook-url
/etc/hermes-multica-bridge/credentials/<instance>/hmac-signing-secret
/etc/hermes-multica-bridge/credentials/<instance>/multica-pat
/etc/systemd/system/hermes-multica-bridge@<instance>.socket.d/10-hermes-user.conf
/run/hermes-multica-bridge/<instance>.sock
/var/lib/hermes-multica-bridge-<instance>/
```

Каталог `/etc/hermes-multica-bridge` и instance TOML содержат только non-secret policy/config и создаются root-owned с правами, позволяющими `DynamicUser` sender прочитать конфигурацию (`0755` для каталога, `0644` для TOML). Подкаталог `credentials/<instance>` остаётся root-only (`0700`), а credential files — `0600`; systemd передаёт их сервису только через `LoadCredential=`.

Systemd при запуске сервиса выдаёт credentials под runtime names:

- `HMB_WEBHOOK_URL`;
- `HMB_HMAC_SIGNING_SECRET`;
- `HMB_MULTICA_PAT`.

PAT file существует даже при отключённом result tracking и тогда может быть пустым. Sender читает PAT только для операции result lookup.

## 1. Установить файлы

Скопировать пакет в root-owned каталог, например:

```bash
sudo install -d -m 0755 /opt/hermes-multica-bridge
```

После копирования проверить, что обычный Hermes OS user не может изменять Python source, systemd units и root-owned config.

Скопировать template units:

```bash
sudo cp deploy/systemd/hermes-multica-bridge@.socket /etc/systemd/system/
sudo cp deploy/systemd/hermes-multica-bridge@.service /etc/systemd/system/
```

Socket unit создаёт общий каталог `/run/hermes-multica-bridge` с root ownership через `DirectoryMode=0755`; DynamicUser sender не владеет этим общим parent и не может подменять sibling sockets.

## Установка Workspace watcher

Workspace routes работают через профильный Hermes plugin process в Standard, а обратные события доставляет отдельный постоянный watcher. Соберите production wheel локально и установите его в отдельный venv watcher; в `/opt/hermes-multica-bridge` не копируйте `.env`, credentials, тесты, memory-bank, `.agents` или development state.

Workspace tools не требуют изменений `PluginContext.register_tool()` или `model_tools`: они используют стандартный вызов инструмента без `pass_context`. В целевой Hermes-сборке должны быть доступны `gateway.session_context.get_bound_session_env()` и `get_current_attachments()`, а inbound adapter обязан устанавливать корректные значения для каждого текущего сообщения. Плагин читает только bound context: его USER_ID должен представлять автора текущего сообщения, а не адресата общей сессии. Пустой bound author блокирует операцию; legacy `get_session_env()` и process env не используются для авторизации.

Это внутренний стык Hermes, помеченный `T38-DEBT-3`; его нужно перепроверять после каждого обновления. Перед включением маршрута выполните `hermes plugins validate` и `hermes plugins doctor --ci` на точной целевой сборке, а также runtime-проверку source IDs и вложения из MAX/Telegram. Doctor подтверждает загрузку плагина, но не доказывает, что Gateway adapter привязал session context во время реального сообщения.

Подготовьте отдельную системную учётную запись `om73-watcher` без login shell и домашнего каталога. Создайте ограниченную группу `hermes-multica-bridge`; добавьте в неё `om73-watcher` и OS account Hermes Gateway. В watcher TOML задайте числовой `socket_gid` этой группы и точный Hermes UID в `allowed_peer_uids`. Проверка `SO_PEERCRED` остаётся обязательной даже при доступе к socket через группу.

Создайте root-owned конфигурацию и независимые systemd credentials. [Redacted-пример](../config/watcher.example.toml) показывает watcher side, а [пример Hermes registry](../config/registry.om73.example.json) — четыре отключённых Workspace routes и один disabled Autopilot route. В локальной конфигурации для `om73` должны быть только утверждённые workspace routes, каждый с конкретными `workspace_id`, `project_id`, платформой, user/chat allowlist, статусами и собственными route ID. Реальные ID не помещаются в исходники или пример.

Для каждого profile создайте независимые credentials `multica-pat`, `max-token` и `telegram-token` с правами `0600`; имя credential должно совпадать с соответствующим `*_credential` в TOML. Не считывайте PAT из Hermes home и не переносите его из старого server config. Установите watcher config как `root:om73-watcher 0640` или строже; файл содержит только non-secret policy.

Соберите wheel, установите его в watcher venv, затем скопируйте unit:

```bash
sudo python3 -m venv /opt/hermes-multica-bridge/watcher-venv
sudo /opt/hermes-multica-bridge/watcher-venv/bin/pip install /path/to/hermes_multica_bridge-0.4.0-py3-none-any.whl
sudo install -m 0644 deploy/systemd/hermes-multica-watcher.service \
  /etc/systemd/system/hermes-multica-watcher.service
```

`StateDirectory` и `RuntimeDirectory` создаёт systemd для watcher. Сервис запускается под `om73-watcher`, применяет `ProtectHome=yes`, читает только объявленные `LoadCredential` и создаёт собственный Unix socket при старте; socket group даёт доступ только `hermes-multica-bridge`. До активации проверьте членство Gateway и watcher в группе, UID allowlist и соответствие имен credentials конфигурации.

Локальная проверка unit:

```bash
systemd-analyze verify deploy/systemd/hermes-multica-watcher.service
```

`systemctl enable --now hermes-multica-watcher.service` относится к отдельному live deployment этапу. Этот план реализации не устанавливает unit и не меняет текущий server runtime.

Предыдущие `/etc/hermes-multica-bridge` и `/var/lib/private/hermes-multica-bridge` не импортируются и не мигрируются. Если их нужно сохранить, заранее сделайте отдельную резервную копию вне путей новой установки: `/etc/hermes-multica-bridge` используется для новой Isolated-конфигурации, а watcher работает только со своими `/etc/hermes-multica-watcher` и `/var/lib/hermes-multica-watcher`.

## 2. Подготовить Isolated instance

Сначала создать Isolated Route в Desktop и скопировать полную команду `Настройка` из instructions. Она содержит только non-secret Route identity и instance ID. Пример формы команды:

```bash
sudo python3 /opt/hermes-multica-bridge/deploy/configure_isolated_instance.py \
  --instance <instance-id-из-Route> \
  --route-id <route-id> \
  --connection-id <connection-id> \
  --workspace-key <workspace-key> \
  --route-policy-fingerprint <route-policy-fingerprint>
```

Helper запрашивает:

- Hermes OS user/UID;
- trusted Gateway systemd unit;
- Multica HTTPS origin;
- Workspace ID;
- Autopilot ID;
- trigger ID;
- разрешённые Hermes boards;
- webhook URL;
- HMAC signing secret;
- read-only PAT, если включён result tracking.

Secret input скрыт. Значения не печатаются.

По умолчанию generated connection остаётся `enabled=false`. Для staged preparation это предпочтительно. Параметр `--enable` следует использовать только когда оператор уже проверил generated config.

## 3. Проверить generated files

Проверить owner/mode:

```bash
sudo ls -ld /etc/hermes-multica-bridge
sudo ls -l /etc/hermes-multica-bridge/<instance>.toml
sudo ls -l /etc/hermes-multica-bridge/credentials/<instance>/
sudo cat /etc/systemd/system/hermes-multica-bridge@<instance>.socket.d/10-hermes-user.conf
```

Не выводить contents credential files.

Проверить non-secret status:

```bash
sudo python3 /opt/hermes-multica-bridge/deploy/status_isolated_instance.py \
  --instance <instance>
```

При запуске внутри systemd helper читает `CREDENTIALS_DIRECTORY` по ID, объявленным в `LoadCredential=` (`HMB_WEBHOOK_URL`, `HMB_HMAC_SIGNING_SECRET`, `HMB_MULTICA_PAT`). При ручной проверке staged каталога используются исходные имена credential files.

В этом pre-enable status `ok` означает, что конфигурация и credentials готовы к активации; это поле намеренно не требует уже созданного socket. Его наличие показывается отдельно как `socket_available` и ожидаемо равно `false` до шага 5. После активации socket фактическую доступность sender проверяет live readiness probe в Desktop/Web status.

## 4. Проверить unit files

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/hermes-multica-bridge@.socket \
  /etc/systemd/system/hermes-multica-bridge@.service
```

## 5. Активировать instance

После проверки сначала явно активировать root-owned sender policy. Повторный запуск helper с `--enable` использует тот же атомарный update/rollback path; оператор должен повторно ввести и сверить те же non-secret значения и credentials:

```bash
sudo python3 /opt/hermes-multica-bridge/deploy/configure_isolated_instance.py \
  --instance <instance> \
  --route-id <route-id> \
  --connection-id <connection-id> \
  --workspace-key <workspace-key> \
  --route-policy-fingerprint <route-policy-fingerprint> \
  --enable
```

Затем ещё раз выполнить `status_isolated_instance.py` и убедиться, что в non-secret status указано `"enabled": true`. Только после этого активировать socket:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hermes-multica-bridge@<instance>.socket
```

Проверить:

```bash
sudo systemctl status hermes-multica-bridge@<instance>.socket
sudo systemctl status hermes-multica-bridge@<instance>.service
```

Socket service может быть inactive между запросами — это нормально для socket activation. После запроса sender остаётся активным до 90 секунд без новых подключений, поэтому обычный polling результата примерно раз в 30 секунд переиспользует один процесс и не расходует systemd start-limit. Sender также прекращает принимать новые подключения после одного часа работы и сначала завершает уже принятое ограниченное по времени обращение. Socket остаётся активен и systemd запустит новый sender при следующем запросе; жёсткий `RuntimeMaxSec` не нужен.

## 6. Активировать Isolated Route в Hermes profile

В **Multica Bridge → Реестр** проверить, что у Route:

- Connection использует `security_mode=isolated`;
- Workspace/Autopilot/trigger/origin/source policy совпадают с operator config;
- route-specific `instance_id` в instructions соответствует подготовленному systemd instance;
- root-owned sender policy уже показывает `enabled=true`;
- Connection и Route включаются только после успешной readiness.

Standard route credentials для Isolated Route не используются.

Desktop/Web status должен показать expected socket path:

```text
/run/hermes-multica-bridge/<instance>.sock
```

При проверке и включении Isolated Route dashboard выполняет локальный live `readiness` probe через этот socket. Подключение активирует sender, поэтому systemd сразу проверяет источники `LoadCredential`; затем sender проверяет root-owned config, webhook fingerprint, HMAC/PAT и совпадение non-secret policy с Route. Probe не вызывает Multica webhook/API и не запускает Autopilot.

## Ротация webhook/HMAC/PAT

Для webhook URL использовать operator helper: он проверяет новый URL и согласованно обновляет credential file вместе с `webhook_sha256` в root-owned instance config. Helper сериализует параллельные ротации одного instance отдельной OS-блокировкой и восстанавливает незавершённую операцию по защищённому журналу. На время ротации рекомендуется остановить instance socket/service, чтобы sender не прочитал файлы между двумя атомарными заменами:

```bash
sudo systemctl stop hermes-multica-bridge@<instance>.socket
sudo systemctl stop hermes-multica-bridge@<instance>.service
sudo python3 /opt/hermes-multica-bridge/deploy/store_webhook_credential.py \
  --instance <instance>
sudo systemctl start hermes-multica-bridge@<instance>.socket
```

HMAC/PAT можно безопасно заменить в соответствующем root-owned credential file, затем перезапустить активный sender instance, если он уже запущен:

```bash
sudo systemctl try-restart hermes-multica-bridge@<instance>.service
```

Socket unit останавливать для ротации обычно не требуется. При подозрении на компрометацию сначала остановить socket, затем заменить credentials и только после проверки снова включить его.

## Немедленная остановка

```bash
sudo systemctl stop hermes-multica-bridge@<instance>.socket
sudo systemctl stop hermes-multica-bridge@<instance>.service
```

После этого выключить Connection/Route в Hermes registry и/или operator config.

Уже начатый внешний HTTPS request мог завершиться до остановки сервиса.

## Чистая установка профиля

Версия продукта — 0.6.0. Статический ConnectionRegistry 0.5.0 продолжает загружаться без переписывания; внутренние версии registry/API не добавляются. Dynamic routes хранятся отдельно на профиль, не содержат credentials и отклоняют неизвестную схему до изменения store. Notify использует собственную миграцию SQLite; старый watcher state не переиспользуется. Credentials задаются через предназначенные Hermes/systemd интерфейсы и не выводятся в терминал или отчёты.

При первом включении Route его destination фиксируется. После появления deliveries нельзя удалять ledger или переиспользовать их `route_id` для другого назначения. Включённый или использованный Route должен остаться в registry и при выводе из эксплуатации перейти в disable + tombstone: result lookup использует immutable snapshot исходной доставки.

## Удаление Isolated instance

Сначала остановить units:

```bash
sudo systemctl disable --now hermes-multica-bridge@<instance>.socket
sudo systemctl stop hermes-multica-bridge@<instance>.service
```

После этого можно удалить instance config, credentials и socket drop-in, выполнить `systemctl daemon-reload`.

StateDirectory/ledger удалять только если больше не нужен audit/idempotency history.

## Live проверка

Локальная installation/readiness проверка не должна сама запускать Multica Autopilot.

Первый живой `multica_send_task` выполняется отдельно из реальной pinned Hermes Kanban task после того, как оператор проверил:

- правильный профиль;
- выбранный/автоматически разрешённый Route и source/profile/assignee/grant policy;
- Connection/Workspace/Autopilot/trigger;
- credential presence именно этого Route;
- HMAC;
- result PAT scope при необходимости.

Если текущему worker разрешено несколько Routes, сначала вызвать `multica_list_routes` и передать выбранный `route_id`. Ответ `accepted` подтверждает доставку, но не завершение Multica task. Результат проверяется отдельно через `multica_check_task_result`; при нескольких deliveries одной task также передаётся конкретный `route_id`.

## Обновление watcher до 0.3.0

Миграция watcher state односторонняя: добавляются deliveries.attempts/next_retry_at/event_type/payload_json и issue_snapshots.status_entered_at/cycle_started_at. Неизвестные схемы отклоняются. Старые mappings, snapshots и seen_comments сохраняются; историческая граница статуса ограничена сохранённым updated_at, историческая граница цикла неизвестна. При известной границе REPORT старого цикла не используется; при неизвестной применяется lookback.

Перед deployment снимите согласованные SQLite backup (через sqlite3 .backup), SHA-256 и S3-копию каждой БД; отдельно сохраните TOML. Проверяйте копии с учётом WAL. После установки quiet включают явно; отсутствие notifications сохраняет verbose. Custom units, credentials, маршруты и cron не заменяются автоматически.

Откат: остановить watcher, восстановить БД и TOML из согласованного снимка, вернуть код 0.2.0 и проверить readiness. Старый код не читает новую схему; mappings и результаты после снимка при таком откате теряются. Живой пилот, перезапуск и изменение cron требуют отдельного этапа.

Старые WAL/SHM нельзя смешивать с восстановленным снимком: восстанавливайте при остановленном watcher через согласованную SQLite backup/restore процедуру, сохраняя прежние файлы для диагностики и исходные owner/mode.

## Регистратор существующих задач (backfill)

Утилита `deploy/tools/multica_watch_register.py` регистрирует существующие задачи через watcher IPC. Она не входит в wheel и не регистрируется в plugin.yaml. Это backfill: после регистрации действует та же политика quiet/verbose соответствующего watcher-маршрута.

Используйте [нерабочий пример с плейсхолдерами](../config/multica-watch.example.json). Задайте профиль watcher, профиль Multica CLI, маршрут, workspace/project, платформу, chat_type, разрешённого пользователя, чат, тред и опорное сообщение. Платформа задаётся явно: max или telegram; MAX thread отклоняется, поскольку точная доставка в MAX-тред не поддерживается. Для dm/group thread_id должен быть null. Журнал и IPC socket задаются параметрами. Реальные ID и приватные пути не публикуйте.

```bash
python3 deploy/tools/multica_watch_register.py --socket /REPLACE/IPC.sock --readiness
python3 deploy/tools/multica_watch_register.py --config /REPLACE/private.json --journal /REPLACE/mappings.json ISSUE-123 --route route-a --dry-run
python3 deploy/tools/multica_watch_register.py --config /REPLACE/private.json --journal /REPLACE/mappings.json --sweep
```

Конфигурация и журнал — приватные файлы 0600 в каталогах 0700. CLI выполняет только чтение issue get/list с закреплёнными profile, HTTPS origin и workspace. Перед IPC проверяется проект. Получателя нельзя заменить аргументами задачи. Dry-run не меняет mapping или журнал; подтверждение сохраняется только после ACK watcher. Повтор sweep идемпотентен; sweep_since задаётся при активации и не сдвигается между проходами.

Коды завершения: 0 — успех; 1 — недоступная или чужая задача; 2 — недоступный IPC/потерянный ACK; 3 — отказ watcher или конфликт mapping; 4 — неверные аргументы, конфигурация, ответ CLI или журнал. Установка утилиты, настройка живых credentials и cron выполняются отдельным этапом.

## Центральный notify 0.4.0

Notify устанавливается в собственный venv и работает под `hermes-notify`. Плагинные tools и старый watcher остаются независимыми. Эта инструкция описывает отдельный deployment-этап; исходники не устанавливают службы автоматически.

1. Сохранить согласованные SQLite backup, TOML, SHA-256 и S3-копии действующего watcher. Не заменять custom units и credentials.
2. Создать системного пользователя `hermes-notify`, StateDirectory/RuntimeDirectory 0700 и приватный каталог конфигурации. Конфигурацией и CLI-файлами владеет hermes-notify; административные CLI-команды выполнять от этого пользователя.
3. Установить wheel 0.6.0 в `/opt/hermes-multica-notify/venv`. Положить unit из репозитория; добавить operator-owned drop-in с точными `LoadCredential=<имя>:<приватный-путь>` для используемых accounts/workspaces. Не создавать пустые credentials.
4. Инициализировать конфигурацию через `init`, заполнить TOML и credentials. Пример содержит нерабочие плейсхолдеры. Основной CLI 0.8.2 должен поддерживать updated-since/until, сортировку и paging; doctor проверяет capabilities. Перед live отдельно проверить точный серверный бинарник.
5. После запуска `run` сервис строит infrastructure projection. Затем добавлять подписки. Изменения workspace через CLI append-only сохраняют комментарии и требуют SIGHUP; invalid reload оставляет рабочую проекцию.

```bash
hermes-multica-notify --config /REPLACE/notify.toml workspace add --name test --origin https://multica.example.invalid --workspace-id REPLACE_UUID --cli-profile notify-test --pat-credential notify-pat-test
hermes-multica-notify --config /REPLACE/notify.toml subscription add --platform telegram --account telegram-test --chat REPLACE_CHAT --chat-type thread --thread REPLACE_THREAD --workspace test --project REPLACE_PROJECT --shadow --label "Тест"
hermes-multica-notify --config /REPLACE/notify.toml import-watcher --watcher-config /REPLACE/watcher.toml --bindings /REPLACE/watcher-bindings.toml --dry-run
hermes-multica-notify --config /REPLACE/notify.toml import-issues --subscription REPLACE_SUBSCRIPTION --dry-run
hermes-multica-notify --config /REPLACE/notify.toml status --json
hermes-multica-notify --config /REPLACE/notify.toml doctor
```

Импорт без dry-run добавляет недостающие инфраструктурные таблицы TOML и запрашивает reload; подписки записываются только после появления проекции в работающем сервисе. Если сервис не запущен, команда сообщает `notify_reload_pending`; после старта её повторяют. Повторный импорт идемпотентен. Реальный bindings-файл имеет 0600, пример — `config/watcher-bindings.example.toml`; получатели из allowlist или старых mappings не выводятся.

`subscription disable ID` отменяет pending/retry; `enable ID` устанавливает since=now. `replay ID` разрешён только для dead/cancelled с retained payload и включённой подпиской. Истёкший payload восстановить нельзя. Shadow — отдельная подписка на явный тестовый чат, не автоматическое перенаправление production-потока.

CLI-профиль создаётся в runtime HOME workspace с правами 0600/0700 из systemd credential. HOME пользователя Hermes и token env не используются; sandbox ProtectHome остаётся включён. SIGHUP не устанавливает новые systemd credentials: новые LoadCredential требуют отдельного root-изменения unit/drop-in и перезапуска.

Полная сверка 300±30 секунд: максимум две одновременно и одна на workspace; polling45s/overlap300s. Наблюдаемость показывает историю, которую источник не смог предоставить. Pending hints объединяются по workspace/issue/type (для `task:failed` отдельно по task ID) и ограничены 10 000 на workspace; при заполнении новые уникальные hints отклоняются, а `status` показывает причину и ограниченность истории. Добавление подписки с историческим `--since` запускает полную сверку доступной истории. Retention: events7d, terminal/replay30d, processed keys весь срок подписки, pending hints без TTL, processed24h/rejected7d.

Пилоты отдельно: shadow24ч → одна production-подписка7д → остальные по одной. Перед включением production отключить соответствующий старый watcher-путь: реестры независимы и не предотвращают двойную доставку между сервисами. Откат: остановить notify, вернуть старые watcher-маршруты, проверить readiness. Notify DB не восстанавливается поверх watcher DB; cron автоматически не меняется.

Notify reload отклоняет изменения db_path, runtime_dir, delivery_workers и request_timeout_seconds: они требуют отдельного перезапуска. Отправки сериализованы до завершения HTTP для консервативного pacing; сбор workspace выполняется независимо. Постоянно недоступные по 403/404 issue из hints изолируются как rejected и не блокируют остальные задачи; текст ответа не журналируется.

## Completion wake 0.5.0

Wake выключен по умолчанию. Его включение требует отдельной loopback webhook platform и route для каждой пары подписка/тема. Не добавляйте route для production темы до проверки тестовой темы, credentials, snapshot-политики и rollback.

1. В `[wake]` настройте loopback `base_url`, root-only HMAC credential и пути к service-owned webhook policy export. Добавьте systemd drop-in `LoadCredential=hermes-wake-hmac:<private-path>`; источник credential должен существовать и быть непустым. Не передавайте HMAC в аргументах.
2. После проверки через поддерживаемый Hermes interface создайте sanitized `webhook-policy.json` по образцу `config/wake-webhook-policy.example.json`. Укажите фактические profile/route/event/target/thread, HMAC presence, toolsets без Multica plugin, отсутствие route script/skills/coalesce и проверенную snapshot-only/final-only политику. Не копируйте `secret` в export.
3. Установите export как `root:hermes-notify 0640` в каталог, доступный этому сервису; он содержит реальные chat/thread IDs. Команда `doctor` и `wake add|enable` сверяют его с destination notify-подписки и запрещают несовпадения.
4. Выполните `hermes-multica-notify doctor`, затем добавьте wake сначала для утверждённой тестовой подписки. Проверьте `wake status --json` и журналы. `wake add` не отправляет пробное сообщение; реальный E2E создаёт тестовую issue и требует отдельной авторизации.

Hermes webhook route должен иметь точные `events = ["task.completed"]`, профиль-получатель, HMAC, `deliver_only=false`, фиксированные `deliver`/`deliver_extra.chat_id`/`thread_id`, выключенные mirror, script, skills и coalesce, а также route toolsets без Multica tools. Prompt ограничивает агента snapshot и одним финальным ответом. При отсутствии подтверждения темы не направляйте ответ в родительский чат.

Одна автоматическая попытка POST не гарантирует exactly-once. `delivery_unknown` не повторяется автоматически. Перед `wake replay ID --confirm` оператор сверяет Hermes journal и целевой тред; тот же wake ID позволяет Hermes дедуплицировать уже принятый запрос, но доставка ответа всё ещё может быть неоднозначной.

Откат: отключить wake-подписки, остановить notify и только затем восстановить согласованные БД/TOML/credential drop-ins. Не удаляйте receipts и сохранённые `delivery_unknown` без записи audit. Gateway restart выполняется только в согласованное окно и после готовности обоих профилей и тестовой цели.

## Scoped Workspace routes 0.6.0

Static routes версии 0.5.0 остаются без переписывания. В `registry.route_grants` оператор отдельно задаёт профиль, connection, workspace, разрешённые project/squad, источник и точный thread/user, typed assignees, credential anchor, лимит маршрутов, auto-approval и срок действия. Не добавляйте реальные токены в registry; PAT anchor задаётся через Hermes credential UI.

Динамические маршруты создаются инструментом `multica_route_create` только из trusted чата. Один совпавший grant выбирается автоматически; при нескольких нужен `grant_id` из перечня текущего контекста. Маршрут остаётся `pending`, пока оператор не одобрит его в Dashboard или не включит `auto_approve` в grant. Отзыв гранта блокирует последующие операции; секреты в dynamic store не сохраняются.

Для конечного набора используйте `project` или `allowlist`. `all_workspace` доступен только динамическому маршруту `scope_kind=workspace` при активном `allow_all_projects=true`, и каждый `multica_workspace_send` требует явный `project_id`. Не переносите статические маршруты в открытый scope. `allowed_thread_ids` — точное ограничение входной темы; оно проверяется до Multica API.

Completion route обязан иметь `wake_mode=completion` и `watcher_enabled=false`; он не нуждается в старом watcher. Readiness берётся из отдельного read-only notify socket и показывается по проектам. Для нескольких проектов общий `wake_ready=true` означает покрытие каждого разрешённого проекта; открытый workspace scope всегда остаётся `false` для общего readiness. Отсутствие notify отображается как warning.

`[readiness_ipc]` по умолчанию выключен. Для локальной интеграции задайте только необходимые UID и Hermes profile в приватном notify TOML, включите read-only сокет и добавьте plugin UID в allowlist. Каталог сокета доступен для traversal (`0711`), сокет — для подключения (`0666`), но каждый peer проверяется по `SO_PEERCRED`/UID/profile до чтения запроса; длина кадра проверяется до JSON parsing. Не открывайте сокет через сеть и не выдавайте ему доступ к Hermes home, notify DB или credentials.

Отдельный DynamicRouteStore создаётся в приватной директории данных профиля. Не копируйте его между профилями и не редактируйте SQLite вручную. При неизвестной схеме сервис прекращает операцию без миграции или изменения файла. Новые и отозванные маршруты становятся видимыми без рестарта Gateway.

В этой реализации T74 не выполняется: package install, live grants/credentials, wake subscriptions, Gateway/notify/watcher restart, canary, Multica issue, production activation и публикация требуют отдельного разрешения и backup/rollback плана.
