# Runtime Router 0.7.0

Этот документ описывает локальную сборку и отдельный операторский запуск Runtime Router. Ветка 0.7.0 не устанавливается автоматически и не меняет существующие маршруты.

## Модель работы

Один canonical Multica agent обслуживает роль. Router хранит principal, привязки runtime и очередь запросов в собственной SQLite базе. Hermes tools только валидируют и ставят запрос в очередь; отдельный CLI worker выполняется таймером systemd и не запускается в plugin thread.

Для одного `(instance_id, agent_id)` допускается только один активный запрос. Worker проверяет отсутствие active/queued runs, при необходимости переключает runtime, сверяет ответ и только затем создаёт issue. Переход агента проверяется по readback. При неопределённом результате создания задача не создаётся повторно автоматически.

Существующие инструменты 0.6.0 остаются прежними на обычных маршрутах. На маршруте с `runtime_router.enabled=true` прямой `multica_workspace_send` закрыт; создавать запрос нужно через `multica_runtime_task_create`.

## Конфигурация

Начните с [runtime-router.example.json](../config/runtime-router.example.json). Все указанные UUID синтетические, профиль CLI и операторские идентификаторы — примеры. Не копируйте этот файл в production без проверки каждого поля.

- Оставьте `enabled=false`, пока не настроены отдельный least-privilege Multica CLI profile, канонический agent, runtime allowlist, principal identities и bindings.
- Укажите абсолютный локальный `state_path`, одинаковый во всех Hermes profiles, которые должны делить очередь. В примере замените `REPLACE_WITH_SERVICE_USER` на имя OS user, которое указано как instance в `hermes-multica-router@<service-user>.service`; путь должен находиться внутри создаваемого этим unit каталога `/var/lib/hermes-multica-router-<service-user>`. `${HERMES_HOME}` запрещён при включённом router, потому что он может отличаться между профилями.
- Родительский каталог БД должен принадлежать OS user Gateway/worker и иметь режим без group/world доступа. Плагин, worker и SQLite используют один UID.
- Для каждого CLI profile задайте фиксированные `instance_id`, workspace и HTTPS origin. Модель не передаёт эти значения.
- `allowed_runtime_ids` — операторское подтверждение доступа canonical agent к runtime. Не выводите их из runtime list автоматически и не добавляйте runtime без согласия владельца.
- `model_by_runtime` задаёт необязательное явное переопределение модели для разрешённого runtime. Без него используется `agent get` model; пустая строка `model=""` означает runtime default и не является ошибкой.
- `allowed_models_by_runtime` — отдельный операторский allowlist. Не выводите его из model policy. Неуказанная явная модель отклоняется.
- `model_policy.enabled` по умолчанию `false`; выбор идёт от разрешённой explicit model к единственному правилу с высшим priority, далее к `model_by_runtime` и runtime default. Конфликт одинакового priority закрывает запрос.
- `capability_source=none` безопасен по умолчанию. Без проверенного каталога fallback запрещён; неизвестную совместимость нельзя считать неподдерживаемой.
- Привязки `strict` игнорируют exceptions и explicit runtime. В `exceptions` применяется priority, затем число совпавших селекторов; равенство закрывает операцию с `rule_conflict`.
- `kanban_mirror` оставляйте `false`. В этой версии нет публичного Hermes projection API у отдельного worker; `true` отклоняется, чтобы не создавать молча no-op конфигурацию.

Плагин публикует безопасный snapshot текущей registry-конфигурации в `state_path.parent/profiles/<profile>.json`. Файлы имеют режим `0600`, каталог — `0700`. Некорректная конфигурация заменяет прежний snapshot disabled-маркером; worker не использует устаревшую политику.

CLI использует отдельный HOME `state_path.parent/cli-home`, а не Hermes HOME. Профиль CLI должен быть заранее создан оператором в этом HOME и иметь только необходимые права. Токен не передаётся в argv, environment variables, JSON config, SQLite или журнал. Не используйте `MULTICA_TOKEN` или другую неподтверждённую token env-переменную.

## Condition wake и approval-ready 0.7.0

Condition wake остаётся выключенным по умолчанию. Notify config также должен содержать `[approval_ipc]` с `enabled=false`, фиксированным socket `/run/hermes-multica-notify-approval/approval.sock`, `native_delivery_suppressed=false` и пустым `peers`. Unit создаёт отдельный runtime directory; не объединяйте этот mapping socket с read-only readiness socket.

До включения оператор обязан доказать на точной целевой Hermes сборке, что native wake/run/comment не доставляет отдельное сообщение пользователю. Пока доказательства нет, оба флага остаются `false`, а `condition_wake` и approval-ready не используются. Локальные fixtures и успешная регистрация wakeup не подтверждают этот gate.

При авторизованной проверке parent сначала создаётся с локальным intent; следующий Workspace update валидирует полный child tree и stage-план, затем регистрирует один native `children_done` wakeup. При staged-конфигурации `stage` и `expected_stage_count` задаются парой и совпадают; unstaged не содержит ни одного поля. Дети должны иметь точные статусы `done`.
Число staged-этапов не превышает 500 — максимальный размер проверяемого дерева; должны присутствовать все номера от 1 до N.

Плагин отправляет в mapping socket только parent/wakeup/route/profile/instruction/expiry. Notify повторно проверяет scope read-only Multica API и принимает только однозначную связь parent, wakeup, run и сохранённых детей. Финальный `task.ready_for_approval` создаётся и отправляется только notify; он не закрывает parent и не выполняет human approval. Mapping socket имеет отдельные `SO_PEERCRED` UID/profile allowlist и кадр до 16 KiB, без доступа плагина к notify DB или credentials.

## Хранилище и повторное выполнение

SQLite находится в WAL, ограничивает один активный запрос на `(instance_id, agent_id)` и использует транзакционные leases с fencing token. Additive migration принимает только документированные схемы; неизвестную схему сервис отвергает без перезаписи.

Повторное сообщение с тем же trusted source key возвращает прежний request. Новый payload с тем же ключом даёт `request_conflict`. После таймаута POST или неподтверждённого ответа request переходит в reconciliation; issue marker ищется read-only перед любым продолжением. Неопределённое создание не запускается повторно вслепую.

Вложения принимаются только из текущего bound Hermes message, проверяются маршрутом и кладутся в приватный spool. CLI получает только сверенный файл из spool. Ссылки и исходные пути не принимаются от модели.

## CLI и обслуживание

Операторские команды работают с приватным JSON, у которого режим `0600`; файл содержит маршрутизацию, но не PAT:

```bash
hermes-multica-router --config /etc/hermes-multica-router/<profile>.json doctor
hermes-multica-router --config /etc/hermes-multica-router/<profile>.json status
hermes-multica-router --config /etc/hermes-multica-router/<profile>.json principal add --display-name '<name>'
hermes-multica-router --config /etc/hermes-multica-router/<profile>.json identity link --principal-id '<uuid>' --connector-id '<connector>' --platform-user-id '<trusted-id>'
hermes-multica-router --config /etc/hermes-multica-router/<profile>.json binding set --principal-id '<uuid>' --instance-id '<instance>' --runtime-id '<allowed-runtime>' --mode strict
hermes-multica-router --config /etc/hermes-multica-router/<profile>.json tick
```

`doctor` читает текущую конфигурацию и профиль Multica, проверяет SQLite, проект, агента, его concurrency limit, доступность runtime и модель. Он не создаёт issue. Не запускайте `tick` для live-профиля как тест: `tick` может создать ранее поставленную задачу.

Файлы `hermes-multica-router@.service` и `hermes-multica-router@.timer` задают один короткий oneshot tick. Unit instance выбирает OS user; он должен совпадать с UID Hermes Gateway, иначе доступ к общей БД и snapshots отклоняется. State path в plugin config, worker JSON и unit должен указывать на один каталог. Unit запускает таймер только после отдельного deployment approval.

```bash
systemd-analyze verify deploy/systemd/hermes-multica-router@.service deploy/systemd/hermes-multica-router@.timer
```

Для CLI-профиля создайте приватный HOME в `state_path.parent/cli-home` от имени OS user сервиса. Выполните login для явного `cli_profile` в этом HOME через поддерживаемый Multica login flow. Не копируйте профиль из Hermes HOME и не используйте token в командной строке.

Перед обновлением сохраните SQLite через SQLite backup API, конфигурацию и JSON registry; запишите SHA-256. Откат: остановить и отключить router timer, вернуть предыдущую версию plugin/config и восстановить совместимый снимок БД. Не удаляйте новые таблицы вручную. Live-маршруты, credentials, worker и Gateway в этом release workflow не меняются.

## T75 — Матрица окружений и проверка CLI

Проверка этой реализации выполнена 2026-11-14. Профили Multica и их содержимое не читались.

| Окружение | `command -v multica` | `multica version` | Путь | Доступный профиль/workspace | Unit / integration / target canary |
|---|---|---|---|---|---|
| Codex workspace (локальная оболочка) | не найден | command not found | — | не проверялись | unit/fixtures доступны; integration и canary недоступны |
| Hermes target | `/usr/local/bin/multica` | `0.8.2`, commit `b7f8efcaa` | `/usr/local/bin/multica` | не выбран и не проверялся | CLI help подтверждает синтаксис; integration JSON и canary не проверялись |
| Hermes Desktop runtime | отдельно не проверялся | отдельно не проверялся | Desktop может иметь bundled CLI вне PATH | Desktop profile не используется для target | не является источником target integration credentials |

На target read-only проверены `multica --help` и help подкоманд `workspace list`, `workspace get`, `project get`, `runtime list`, `agent get`, `agent tasks`, `agent update`, `issue list`, `issue create`, `issue get`, `issue update` и `issue status`. Подтверждены имена команд, перечисленные флаги, `--output json`, `agent tasks --before`, issue list `--offset/--fields`, create `--description-stdin/--assignee-id/--attachment` и update `--no-start`. Исходники версии 0.8.2 дополнительно подтверждают команды `auth status` и `workspace member list --output json`, которые адаптер использует для проверки runtime access.

Help не подтверждает фактические JSON response shapes или доступ сервиса. Сверка исходников Multica CLI v0.8.2 подтверждает, что `runtime list` возвращает строки `/api/runtimes` без полей `accessible` и `models`. Адаптер сопоставляет пользователя из `auth status` с `user_id` из `workspace member list` и вычисляет доступ по `owner_id`, `visibility` и `shared_with`; неоднозначная или неполная identity закрывается. Каталог моделей CLI 0.8.2 не предоставляет: явная операторская модель проверяется по `agent get` readback, а её фактический запуск остаётся непроверенным до target canary.

На target не выполнялись workspace/project/runtime/agent/issue API reads, runtime switch, issue write, canary или production операция. Поэтому интеграционный контракт остаётся `NOT VERIFIED` для фактических полей:

Condition wake/approval acceptance на target, включая доказательство подавления native-доставки, также остаётся `NOT VERIFIED`; feature должен оставаться выключенным до отдельного разрешения и canary-проверки.

- workspace list: список `workspaces` и ID;
- project get: `id` и `workspace_id`;
- runtime list: `id`, `workspace_id`, `owner_id`, `visibility`, `shared_with`, `status`; `accessible` вычисляется адаптером, `models` в 0.8.2 не выдаётся;
- auth status email ↔ workspace member list `user_id`;
- agent get: `id`, `runtime_id`, `model`, `max_concurrent_tasks`;
- agent tasks: статусы runs и stderr cursor `More runs available; use --before "…"` на полной странице;
- issue list/get/create/update: обёртка JSON, project/workspace/assignee, marker, issue ID и readback;
- real CLI login/profile selection в service-owned HOME, фактический output при отказе/таймауте и target execution выбранной модели.

Перед target canary владелец должен назначить отдельный profile, workspace/project, canonical test agent, два разрешённых runtime и тестовых получателей. До подтверждения этих JSON контрактов и canary-политики не включайте `runtime_router`, не запускайте timer и не ставьте issue. Тесты fixtures проверяют принятые структуры, но не заменяют эту проверку.

Для локальных проверок используйте `pytest -q tests/test_runtime_router.py`, fake adapter и синтетические данные. Скрытого HTTP fallback нет: все Multica операции проходят через установленный `/usr/local/bin/multica` и фиксированные profile/workspace параметры.
