# Changelog

## 0.6.0

- Добавлены project/squad/workspace scopes, точные thread ACL и динамические Workspace-маршруты в пределах операторских route grants.
- Добавлен `multica_route_create`; неоднозначный grant требует выбора только среди разрешённых текущему сообщению вариантов, новый маршрут по умолчанию остаётся pending.
- Динамические маршруты используют статический credential anchor без копирования PAT; отдельная профильная SQLite база обеспечивает идемпотентность, quota, audit и отзыв.
- Completion-маршруты не требуют старого watcher; добавлен read-only notify readiness IPC с `SO_PEERCRED`, UID/profile ACL и per-project статусом.
- Добавлены Dashboard review actions и packaged Hermes Skill; legacy 0.5.0 routes остаются без автоматического переписывания.
- Product version is 0.6.0. This source change does not install, enable, or publish routes.

## 0.5.0

- Исправлены идемпотентность wake enable, остановка ожидающих workers, запрет обычных retry после wake-регистрации, выбор CLI alias и точность doctor; webhook transport проверяет полноту ответа и ограничивает общую длительность запроса.
- Added completion wake jobs for newly observed transitions to `done`, with immutable read-only snapshots and one HMAC V2 request to a profile-scoped loopback Hermes webhook.
- Added additive notify database migration, wake subscriptions/receipts, exact destination validation through a protected webhook policy export, and suppression of regular notifications for registered wake subscriptions.
- Classified webhook admission using both HTTP status and response JSON; `ignored` is terminal, `duplicate` is accepted, and uncertain transport outcomes require operator-confirmed replay.
- Added bounded snapshot payloads, wake CLI commands, safe route diagnostics, and deployment guidance for credentials, backups, test targets, and rollback.
- Product version is 0.5.0. Package installation does not enable live configuration or production routes.

## 0.4.0

- Центральный сервис hermes-multica-notify: подписки Telegram/MAX, isolated CLI profiles, WS/poll recovery и durable outbox.
- Quiet/verbose, REPORT текущего цикла, typed squad и labels AND, bounded retries, lease fencing, dead-letter/replay.
- TOML reload, explicit disabled watcher import, baseline issue import, shadow marker, private status/doctor и отдельный systemd unit.
- Исправлена доступность сканирования при невалидной задаче, pacing Telegram-групп, retry HTTP 408 и обработка чрезмерно вложенного JSON; очередь WS hints ограничена с сохранением полной сверки для исторических подписок.
- Существующие intake/tools/watcher сохраняют поведение; live deployment и пилоты выполняются отдельно.

## 0.3.0

- Явная quiet-политика watcher, bounded retries и durable payload.
- REPORT после паузы включается в final; cancelled включается отдельно.
- Миграция state односторонняя; откат через согласованные снимки БД/TOML.

## 0.2.0

- Workspace assignees теперь используют типизированные Multica identities `member`, `agent` и `squad`; Autopilot сохраняет строковый Hermes assignee allowlist.
- Добавлены default assignee, проверка принадлежности typed allowlist, controlled unassign и диагностика legacy Workspace strings.
- После Workspace create/update выполняется отдельный readback; подтверждённый POST/PUT не повторяется при ошибке проверки.
- Добавлены pseudonymous issue metadata и validated related issue IDs, хранящиеся в primitive metadata value.
- Pseudonymous `requester` и `source_message_id` усилены до HMAC-SHA-256 с domain-separated ключом, производным от профильного Multica PAT маршрута.
- Неназначенная issue возвращает `ok:false` и получает одну terminal notification attempt через публичный Hermes `ctx.post_message()`.
- Desktop, Dashboard, route listing, examples и release metadata показывают typed assignees без раскрытия credentials.
- Удалено неиспользуемое `api_version`; Hermes manifest остаётся формата `manifest_version: 2`.

## 0.1.0

- Добавлен `ConnectionRegistry`: один Hermes profile поддерживает несколько независимых Connections, Workspaces и Routes; entity IDs используют UUIDv7.
- Добавлены три route-safe инструмента Hermes: список доступных Routes, отправка текущей pinned Kanban-задачи и чтение результата ранее созданной доставки.
- Standard использует отдельные route-scoped webhook/HMAC/PAT credentials через Hermes plugin credential API и `agent.secret_scope`.
- Isolated использует отдельный systemd template instance на каждый Route с собственными socket, config, credentials и ledger state.
- Добавлены HMAC-SHA256, стабильные route-scoped idempotency keys, bounded retries/rate limits, HTTPS origin/path validation, запрет redirects/proxy environment и абсолютные network deadlines.
- Добавлен SQLite ledger с immutable destination snapshot, result tracking, monotonic Issue revision ordering и deduplicated Hermes comments.
- Добавлены trusted pinned task/run checks, source/profile/assignee policies и optional exact OperatorGrant.
- Добавлены native Desktop и web dashboard для non-secret topology, readiness, route-scoped credentials и Isolated instructions.
- Isolated требует Linux 6.5+, `SO_PEERPIDFD` и unified cgroup v2; cgroup v1/hybrid layout отклоняется fail closed.
- Добавлены Workspace routes для чатов, четыре инструмента работы с issues, комментариями и статусами, проверка source/workspace/project и прикрепление handles текущего сообщения.
- Добавлен отдельный watcher для событий Multica, polling reconciliation и at-most-once MAX/Telegram уведомлений.
- Watcher повторяет только подтверждённые HTTP 429, ограничивает Telegram по чату и сохраняет прогресс issue/comment до успешной или терминальной доставки; Workspace повторяет IPC mapping из сохранённого источника.
- Hermes dispatch API передаёт opted-in tools доверенный per-message context и открывает текущие вложения через ограниченный public broker.
- Workspace operations используют профильный ledger; подтверждённые операции кэшируются, а неизвестный результат записи не повторяется автоматически.
- Утверждена clean-start модель конфигурации и state stores: прежние development state/config не читаются и не мигрируются; внутреннее API versioning не вводится.
