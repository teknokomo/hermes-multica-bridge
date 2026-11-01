# Security

## Модель угроз

Bridge соединяет доверенный контекст Hermes Kanban с заранее настроенным Multica connection. Основные защищаемые данные и действия:

- secret webhook URL;
- HMAC signing secret;
- read-only Multica PAT;
- выбор Workspace/Autopilot/trigger;
- содержимое исходной Hermes task;
- возможность создать Multica run;
- возможность прочитать результат ранее созданного run;
- целостность локального ledger и comment dedupe.

## Основные инварианты

- Инструменты не принимают model-supplied URL, credentials, destination или task body.
- Title/body читаются только из текущей pinned Hermes Kanban task.
- Source board, текущий run profile, assignee и state должны удовлетворять policy выбранного Route; при включённом `operator_grant_required` требуется точный grant `(board, task_id, route_id)`.
- Destination определяется только валидированным `ConnectionRegistry`; модель может передать только необязательный `route_id`.
- При включении Route его destination фиксируется. Включённый или уже использованный Route нельзя удалить или перенаправить; вывод из эксплуатации выполняется через disable + tombstone.
- Webhook принимает только HTTPS с точным configured origin и допустимым path.
- Redirects и environment proxy variables не используются.
- HMAC подписывает точные байты HTTP body.
- Stable idempotency не зависит от конкретного worker run и partitioned по `route_id`, поэтому одна task может иметь независимые доставки в разные Route.
- Result lookup использует только `run_id` и immutable destination snapshot, сохранённые при исходной доставке.
- Изменившаяся после доставки карточка блокирует result lookup как `request_conflict`.
- Webhook acceptance не считается завершением Multica task.
- Секреты не возвращаются в tool responses, dashboard/Desktop status, logs, ledger, fixtures или review reports.

## Workspace source и операции

- Плагин не регистрирует инструменты с `pass_context` и не принимает source fields в аргументах модели. Для целевой Hermes-сборки он читает текущий turn через `gateway.session_context`: `get_bound_session_env()` подтверждает task-local привязку, а `get_session_env()` должен вернуть те же значения. Несовпадение или неполный контекст означает отказ до Multica write. Это внутренний Hermes API и ограничение совместимости `T38-DEBT-3`; его контракт нужно перепроверять после обновления Hermes.
- Workspace route проверяет платформу и точное членство user/chat IDs в allowlist. Group/channel/thread недоступны без отдельного `allow_groups=true`.
- Workspace route всегда требует настроенные `workspace_id` и `project_id`; каждый читаемый или изменяемый issue проверяется по обоим ID. Parent issue подзадачи проверяется по той же паре.
- Assignee и status ограничены route allowlist. Создание подзадачи требует разрешённого человеческого assignee. Инструмент не приглашает пользователей и не изменяет доступ к пространствам.
- Workspace доступен только в Standard с профильным PAT. Профильные записи, инструменты и локальный ledger не читают прежние development-конфиги или state stores.
- Каждая операция записи привязана к профилю, маршруту, источнику и типу операции. Повтор подтверждённой операции возвращает сохранённый ответ; изменённый payload для той же source operation отклоняется. Только ответ, доказывающий отказ до принятия, допускает новую попытку. Transport/5xx/невалидный ответ фиксируется как `operation_unknown`, POST не повторяется автоматически.

## Вложения текущего сообщения

- Hermes `get_current_attachments()` выдаёт descriptors только для активного Gateway turn; helper сам исключает `image/*`.
- Плагин сверяет `message_id`, platform, chat type, chat ID и actor с тем же task-local session context. Путь принимается только из descriptor Hermes, никогда из аргументов модели.
- Перед чтением плагин проверяет обычный файл и размер, открывает его с `O_NOFOLLOW`, сравнивает `lstat` с `fstat` и повторяет сверку после чтения. Изменившийся файл, symlink, чужой источник, неподходящий MIME/extension либо превышение count/size прерывает создание до первого Multica write.
- Multipart формируется из памяти; временные файлы не создаются. Путь не сохраняется в state, не возвращается инструментом и не включается в сообщения об ошибках. Изображения этой версией Gateway helper-а не предоставляются.

## Изолированный watcher

- `hermes-multica-watcher.service` запускается отдельным `om73-watcher`, имеет `ProtectHome=yes`, собственные root-owned config, `LoadCredential`, `StateDirectory` и профильный приватный SQLite state.
- IPC использует Unix socket с ограниченной группой, ограниченным размером frame и проверкой UID через `SO_PEERCRED`. До сохранения mapping watcher заново читает issue из Multica и сверяет workspace/project. Mapping фиксируется до успешного ответа IPC.
- WebSocket принимает только известные Multica event names; polling сверяет issue и comments. События без сохранённого mapping игнорируются, собственные комментарии watcher не рассылаются.
- После подтверждения доставки сохраняется `delivered`; доказанный отказ — `not_sent`; неизвестный исход — `delivery_unknown` без повтора. Только явный HTTP 429 можно повторить при следующей сверке, поскольку платформа подтвердила, что запрос не принят. Telegram отправляется с интервалом по чату, MAX сохраняет свой лимит. Неудачный IPC mapping остаётся в профильном ledger и повторяется при следующих разрешённых Workspace операциях с исходными сохранёнными source fields; `get` не создаёт mapping из текущего контекста.
- MAX/Telegram отправка отвечает на исходный message ID. Telegram thread использует исходный `message_thread_id`; MAX reply использует исходный message ID. При отсутствии точного reply target сообщение не отправляется в родительский чат.

## Standard mode

Standard хранит non-secret topology в профильном `ConnectionRegistry`.

Каждый Route имеет отдельные logical credentials типов `webhook|hmac|pat`. Публичный Hermes plugin credential API принимает только plugin ID, UUIDv7 `route_id`, фиксированный credential type и profile scope. Hermes детерминированно строит opaque env name; arbitrary env target и reveal через этот API отсутствуют.

Bridge не читает `.env` напрямую и не создаёт собственное secret storage. Runtime вычисляет тот же deterministic key и получает значение только через `agent.secret_scope.get_secret()`.

Профильная граница Hermes остаётся внешней границей secret scope, а внутри одного профиля Route дополнительно изолированы собственным credential namespace. Один профиль может содержать несколько независимых Connections/Workspaces/Routes.

## Isolated mode

Isolated предназначен для случая, когда plugin process не должен иметь доступ к Multica secrets.

Isolated mode требует Linux **6.5+** с `SO_PEERPIDFD` и unified **cgroup v2**. `SO_PEERPIDFD` закрепляет worker process, а отдельный `pidfd_open()` закрепляет его непосредственного Gateway parent на время проверки; после чтения cgroup sender повторно сверяет PPID worker и liveness parent. При невозможности получить pidfd или подтвердить прежнюю связь sender fail closed. Sender также проверяет наличие v2 controller root и fail closed на cgroup v1/hybrid layout, потому что авторизация корневого процесса worker scope опирается на единый `cgroup.procs` путь.

Sender использует:

- Unix socket с ограниченным владельцем;
- systemd socket activation;
- `DynamicUser`;
- root-owned non-secret config;
- systemd `LoadCredential=`;
- отдельный StateDirectory/SQLite ledger;
- `SO_PEERCRED`;
- `SO_PEERPIDFD` для исходного peer и отдельный pidfd для проверки прямого Gateway parent;
- UID allowlist;
- проверку точной transient Kanban worker cgroup и её leader PID;
- проверку `task_id` по launch argv самого Hermes Kanban worker;
- проверку происхождения worker process от настроенного trusted Gateway unit;
- default-deny config.

Peer/process проверки выполняются до чтения request body, а task/run scope проверяется повторно после разбора bounded envelope. К IPC допускается только корневой процесс worker scope, непосредственный родитель которого находится в точно настроенном trusted Gateway systemd unit. После разбора envelope sender дополнительно требует, чтобы `task_id` совпадал с task ID в `-q "work kanban task …"`, с которым Gateway запустил этот worker. Дочерние model-owned процессы и оставшиеся после завершения worker orphan-процессы отклоняются.

Текущая модель авторизации проверяет текущую pinned Hermes task по её runtime identity, а не по model-supplied metadata. Standard получает canonical task, run profile, assignee и state напрямую из Hermes Kanban state и требует, чтобы `tasks.worker_pid` и `task_runs.worker_pid` совпадали с PID текущего plugin process. Isolated принимает только корневой процесс точной `task_id`/`run_id` worker cgroup в ожидаемом user-systemd пути для UID из `SO_PEERCRED`; cgroup и `/proc` проверки используют pidfd исходного peer, полученный через `SO_PEERPIDFD`, и завершаются отказом, если процесс исчез. Корневой PID scope должен быть непосредственным дочерним процессом процесса из точно настроенного Gateway systemd unit, а его launch argv должен подтверждать тот же `task_id`. Это не позволяет model-owned subprocess получить полномочия другой карточки простым созданием или сменой transient scope.

Сам Hermes Kanban worker process и код загруженных в него plugins входят в trusted computing base. Isolated защищает Multica credentials и IPC от модели и запускаемых ею дочерних процессов; произвольное выполнение нативного кода непосредственно внутри процесса worker уже означает компрометацию этой trusted boundary и не рассматривается как изолируемый model subprocess.

Каждый Isolated Route создаёт отдельный template instance на Route, поэтому socket/config/systemd credentials/state разделены. Instance ID выводится из canonical UUIDv7 Route и проверяется до построения socket/config paths.

Root и оператор, способный заменить trusted Gateway unit, systemd units, config или credentials, входят в trust boundary.

Isolated installer проверяет всю цепочку каталогов от выбранного installation root до config/credential/drop-in paths: каждый каталог должен принадлежать текущему оператору (root при реальной установке), быть обычным каталогом без symlink и не иметь group/world write bits.

## Secrets

### Webhook URL

Webhook URL является bearer credential. Он не должен попадать в:

- Git;
- command-line arguments;
- shell history;
- logs;
- screenshots/reports;
- issue/PR text;
- test fixtures.

Isolated helper принимает его интерактивно со скрытым вводом.

### HMAC

При `hmac_enabled=true` пустой signing secret запрещён. Подпись:

```text
X-Hub-Signature-256: sha256=<HMAC-SHA256(raw_body)>
```

Serialization выполняется один раз. Нельзя пересобирать JSON после вычисления подписи.

### PAT

PAT используется только для read-only result path. Он не участвует в webhook send и не используется для provisioning Multica.

При отключённом result tracking PAT не требуется runtime, но Isolated installer создаёт пустой credential file, чтобы systemd template оставался детерминированным.

## HTTP hardening

Клиенты bridge:

- используют стандартную TLS certificate validation;
- не следуют redirects;
- игнорируют proxy environment;
- ограничивают timeout;
- применяют один абсолютный monotonic deadline к DNS, connect/TLS, HTTP headers и body webhook-операции; DNS lookup изолирован bounded daemon resolver с максимум четырьмя одновременно зависшими системными lookup;
- применяют один абсолютный monotonic deadline ко всей result lookup цепочке run → issue → comments;
- ограничивают размер HTTP response;
- строго разбирают JSON и отклоняют duplicate keys;
- не включают response body в публичные ошибки.

Enabled Isolated Route дополнительно требует SHA-256 fingerprint webhook URL. Поэтому замена bearer URL на другой допустимый Multica webhook path без одновременного изменения root-owned config отклоняется.

## Idempotency и retries

Одна логическая версия Hermes task получает стабильный request fingerprint и `Idempotency-Key`.

Ledger ограничивает:

- число попыток на логическую задачу;
- общий rate `Connection` в временном окне: перед Standard или Isolated send плагин атомарно резервирует запрос в profile-wide ledger по `connection_id`, поэтому все Routes и Isolated instances одного Connection делят лимит; Isolated sender дополнительно сохраняет такой же per-instance предел как локальную защиту;
- конкурентные/stale state transitions.

Result snapshots одного статуса с server revision не принимают уменьшение `Issue.revision`; равная revision может содержать новые run/comment данные и потому упорядочивается monotonic poll generation. Для unversioned Issue используется только poll generation, без присваивания ему revision из комментария. Свежая pending reservation результата временно блокирует смену fingerprint, чтобы параллельная проверка не могла опередить публикацию уже подготовленного Hermes-комментария.

Повторный worker run не создаёт новую логическую доставку в том же Route, пока title/body не изменились. Та же Hermes task может иметь отдельную доставку и отдельный idempotency key в другом Route.

## Result comments

Multica result comment имеет скрытый marker с request ID и SHA-256 fingerprint, поэтому одинаковый result fingerprint двух независимых deliveries не смешивает dedupe.

Запись использует двухфазную reservation:

1. ledger резервирует fingerprint;
2. Hermes comment записывается в текущую pinned task;
3. reservation подтверждается только после успешной записи.

При ошибке записи reservation освобождается. Hermes-side dedupe дополнительно проверяет marker в существующих comments.

## UI и диагностика

Web dashboard и native Desktop могут показывать:

- Connections/Workspaces/Routes и per-route readiness;
- non-secret registry;
- per-route presence flag секретов;
- safe delivery/run IDs;
- route-specific Isolated socket/status/instructions.

Они не возвращают secret values.

Registry endpoint принимает только non-secret `ConnectionRegistry`, отклоняет неизвестные поля на каждом уровне схемы и сохраняет его через штатный Hermes `save_plugin_settings`. Так незнакомые значения, включая случайно добавленные credential-поля, не попадают в профильные settings или ответ API. Secret values через plugin backend не принимаются. Standard credentials записываются только через Hermes `ctx.credentials`. Запросы Desktop передают профиль сфокусированной сессии как `?profile=`, а credential calls передают тот же profile scope в Hermes host API.

Backend не разрешает включить Route без обязательных destination/policy fields и readiness. Для Standard проверяется presence именно его route-scoped credentials; для Isolated требуются HMAC, обязательные non-secret поля и успешный live `readiness` probe через route-specific instance socket. Probe доступен только процессу настроенного Gateway, не принимает task payload, не выполняет внешний HTTP и проверяет root-owned config, `LoadCredential`, webhook fingerprint, HMAC/PAT и non-secret policy fingerprint.

Profile/generation guards отбрасывают stale status/save/credential responses после переключения профиля, в том числе A→B→A.

## Lifecycle конфигурации

Версия продукта — 0.2.0. Registry и пустые state stores создаются для текущей архитектуры; неизвестные поля и несовместимые SQLite schema отклоняются без migration path или внутренних версий API/state.

Переход Standard ↔ Isolated не переносит секреты автоматически. Новый Route/режим включается только после отдельной readiness-проверки. Ledger сохраняет immutable delivery snapshot, поэтому rename/disable/tombstone текущего Route не меняет destination уже созданной delivery.

## Проверка перед публикацией

Release gate должен включать:

- offline unit/regression tests;
- compile check;
- Ruff;
- Bandit;
- package build и metadata inspection;
- Hermes `plugins validate`;
- Hermes `plugins doctor` на clean staging без `.ontoindex`, caches и runtime state;
- `systemd-analyze verify` для template units;
- scan на credentials, реальные IDs, host/user-specific значения и пилотные остатки;
- Thermos review;
- terminal Autoreview status.

Локальный PASS не доказывает корректность live VPS, Multica credentials, Autopilot или systemd deployment.
