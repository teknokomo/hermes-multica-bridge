# Changelog

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
