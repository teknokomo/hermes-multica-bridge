# Развёртывание Hermes Multica Bridge 0.1.0

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
Для Isolated 0.1.0 требуется Linux 6.5+ с `SO_PEERPIDFD` и unified cgroup v2; cgroup v1/hybrid не поддерживается и будет отклонён fail closed. На старом ядре sender откажет до чтения IPC-запроса.

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

Workspace tools не требуют изменений `PluginContext.register_tool()` или `model_tools`: они используют стандартный вызов инструмента без `pass_context`. В целевой Hermes-сборке должны быть доступны `gateway.session_context.get_bound_session_env()`, `get_session_env()` и `get_current_attachments()`, а inbound adapter обязан устанавливать корректные значения для каждого текущего сообщения. Плагин сравнивает bound context с `get_session_env()` и отказывает при расхождении.

Это внутренний стык Hermes, помеченный `T38-DEBT-3`; его нужно перепроверять после каждого обновления. Перед включением маршрута выполните `hermes plugins validate` и `hermes plugins doctor --ci` на точной целевой сборке, а также runtime-проверку source IDs и вложения из MAX/Telegram. Doctor подтверждает загрузку плагина, но не доказывает, что Gateway adapter привязал session context во время реального сообщения.

Подготовьте отдельную системную учётную запись `om73-watcher` без login shell и домашнего каталога. Создайте ограниченную группу `hermes-multica-bridge`; добавьте в неё `om73-watcher` и OS account Hermes Gateway. В watcher TOML задайте числовой `socket_gid` этой группы и точный Hermes UID в `allowed_peer_uids`. Проверка `SO_PEERCRED` остаётся обязательной даже при доступе к socket через группу.

Создайте root-owned конфигурацию и независимые systemd credentials. [Redacted-пример](../config/watcher.example.toml) показывает watcher side, а [пример Hermes registry](../config/registry.om73.example.json) — четыре отключённых Workspace routes и один disabled Autopilot route. В локальной конфигурации для `om73` должны быть только утверждённые workspace routes, каждый с конкретными `workspace_id`, `project_id`, платформой, user/chat allowlist, статусами и собственными route ID. Реальные ID не помещаются в исходники или пример.

Для каждого profile создайте независимые credentials `multica-pat`, `max-token` и `telegram-token` с правами `0600`; имя credential должно совпадать с соответствующим `*_credential` в TOML. Не считывайте PAT из Hermes home и не переносите его из старого server config. Установите watcher config как `root:om73-watcher 0640` или строже; файл содержит только non-secret policy.

Соберите wheel, установите его в watcher venv, затем скопируйте unit:

```bash
python3 -m venv /opt/hermes-multica-bridge/watcher-venv
/opt/hermes-multica-bridge/watcher-venv/bin/pip install /path/to/hermes_multica_bridge-0.1.0-py3-none-any.whl
sudo install -m 0644 deploy/systemd/hermes-multica-watcher.service \
  /etc/systemd/system/hermes-multica-watcher.service
```

`StateDirectory` и `RuntimeDirectory` создаёт systemd для watcher. Сервис запускается под `om73-watcher`, применяет `ProtectHome=yes`, читает только объявленные `LoadCredential` и создаёт собственный Unix socket при старте; socket group даёт доступ только `hermes-multica-bridge`. До активации проверьте членство Gateway и watcher в группе, UID allowlist и соответствие имен credentials конфигурации.

Локальная проверка unit:

```bash
systemd-analyze verify deploy/systemd/hermes-multica-watcher.service
```

`systemctl enable --now hermes-multica-watcher.service` относится к отдельному live deployment этапу. Этот план реализации не устанавливает unit и не меняет текущий server runtime.

На сервере прежние `/etc/hermes-multica-bridge` и `/var/lib/private/hermes-multica-bridge` остаются read-only архивом до отдельного принятия новой установки. Новый watcher использует только собственные `/etc/hermes-multica-watcher` и `/var/lib/hermes-multica-watcher`; старые конфиги и ledger не импортируются.

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

Версия остаётся 0.1.0. ConnectionRegistry, Workspace watcher config и оба state stores создаются для текущей архитектуры с нуля. Неизвестные поля и несовместимые базы отклоняются; миграция внутренних форматов отсутствует. Credentials задаются заново через предназначенные для них Hermes/systemd интерфейсы и не выводятся в терминал или отчёты.

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
