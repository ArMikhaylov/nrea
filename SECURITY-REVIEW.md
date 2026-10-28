# Ревью безопасности и качества кода форка `ArMikhaylov/nrea`

База: `morluto/rea` @ `64196b0` (v6.8.0). Ветка с исправлениями: `security-hardening`.

Область ревью: Python-мосты (`bridge/**/*.py`, ~4.5k строк, построчно + `ruff`),
MCP-транспорт (stdio/HTTP), тулы с произвольными командами, распаковка
архивов, редактирование захваченного трафика, HTTP-сервер RL-окружений.
Не покрыто: ~170k строк парсеров форматов в `src/domain` (нужен фаззинг),
`setup`/`update`, Frida-агент, браузерная автоматизация целиком.

---

## 1. Что исправлено в этой ветке

| # | Проблема | Серьёзность | Статус |
|---|---|---|---|
| 1 | MCP-тулы с произвольными командами (`execute_rizin_command`, `rizin_debug_command`, `cutter_command`, `gdb_console`, `load_frida_script`, `instrument_with_frida`) доступны агенту по умолчанию → prompt injection из анализируемого файла даёт выполнение кода на хосте (`!cmd` в Rizin, `shell`/`python` в GDB, JS во Frida) | Критично | **Исправлено**: по умолчанию отказ, опт-ин `REA_MCP_UNRESTRICTED_COMMANDS=enabled` |
| 2 | `rea mcp --http` без аутентификации: любой локальный процесс / другой пользователь ОС на loopback получает все тулы | Критично | **Исправлено**: обязательный `Authorization: Bearer`, токен из `REA_MCP_HTTP_TOKEN` или случайный на процесс |
| 3 | Cutter-мост: TCP на loopback, hello читается с лимитом до 512 MiB → DoS по памяти и занятие 8 слотов без знания секрета | Средняя | **Исправлено**: на Linux/macOS Unix-сокет в каталоге `0700`, hello ≤ 1 KiB |
| 4 | Захват трафика вырезает только `Authorization/Proxy-Authorization/Cookie/Set-Cookie`; API-ключи в заголовках уходят в Evidence и далее к LLM-провайдеру | Средняя | **Исправлено**: + `X-Api-Key`, `Api-Key`, `X-Auth-Token`, `X-Access-Token`, `X-Amz-Security-Token`, `X-Goog-Api-Key` (TS и Python, дубликат списка в `PlaywrightNetworkContent.ts` удалён) |
| 7 | pwndbg-адаптер неявно полагается на `cwd == stage` (относительные пути для GDB) | Низкая | **Исправлено**: явная проверка, иначе отказ |
| 14 | Распаковка на Windows: не отсекались `CON`, `NUL`, `AUX`, `COM1`…, `LPT1`… и имена с точкой/пробелом в конце | Низкая | **Исправлено** |

### Снятые находки первого ревью (оказались ложными)

- **№5 «ложное вырезание» в `capture.py`** — сравнение секрета с дайджестом и длиной
  намеренное: контракт (`src/domain/webNetworkCapture.ts:64`) обещает, что литерал
  секрета не появится нигде в выводе; пустой секрет запрещён схемой (`min(1)`).
  Это избыточная осторожность, не баг.
- **№6 «кеш по `id()` в Hopper-мосте»** — мост держит сильную ссылку на свой
  единственный документ (`_rea_session_document`), поэтому `id()` не может
  переиспользоваться, пока мост жив.

### Детали исправлений

**Гейт произвольных команд** — `src/config/mcpUnrestrictedCommands.ts`,
`src/server/EvidenceMcpServerCore.ts` (`registerTool`), `src/server/createServer.ts`.
Проверка стоит в единой точке регистрации тулов, поэтому работает и в eager-,
и в deferred-рантайме. Тулы остаются в каталоге (catalog identity не меняется),
но вызов возвращает `ConfigurationError` с именем настройки и инструкцией не
повторять вызов. CLI-команды (их набирает человек) не затронуты. Невалидное
значение настройки — ошибка старта, а не тихое «выключено».

**Bearer-токен для HTTP** — `src/config/mcpHttpEndpoint.ts`
(`resolveMcpHttpBearerToken`), `src/server/http/serveStreamableHttp.ts`
(`bearerTokenMatches`), `src/main.ts`. Сравнение SHA-256 дайджестов через
`timingSafeEqual` (не утекают длина и префикс). Проверка до Host/сессии/роутов,
ответ `401` + `WWW-Authenticate: Bearer`. Токен удаляется из `process.env`
после чтения, чтобы не наследовался провайдерами. Сервер RL-окружений
(`rea environment serve`) этой проверкой **не** затронут — см. раздел 2.

**Cutter-мост** — `bridge/cutter/rea_bridge.py`, `src/cutter/CutterBridgeClient.ts`.
Дескриптор публикует ровно один транспорт (`socket_path` или `host`+`port`),
клиент проверяет, что сокет лежит в каталоге моста. `umask` намеренно не
трогается (он общий для процесса Cutter): каталог `0700` уже исключает чужих
пользователей, после `bind` выполняется `chmod 0600`. Также убран
динамический атрибут `stopping` (теперь объявлен в `__init__`).

### Проверка

- `tsc --noEmit` — без ошибок; `oxlint` — без новых ошибок; `oxfmt` — применён.
- Python-протокол Cutter: `tests/fixtures/cutter_bridge_protocol_test.py` — 33/33,
  включая новые тесты на Unix-сокет (`0600`, каталог `0700`, удаление при остановке)
  и на лимит hello.
- Vitest (focused): гейт, Cutter (14 файлов), Frida/Cutter MCP, HTTP unit-тесты,
  распаковка — см. раздел «Результаты тестов» ниже.
- `npm audit` — 0 уязвимостей (prod и dev).

### Breaking changes

1. MCP-вызовы шести тулов произвольных команд по умолчанию отклоняются.
   Включение: `REA_MCP_UNRESTRICTED_COMMANDS=enabled` в env MCP-регистрации.
2. `rea mcp --http` требует `Authorization: Bearer <token>`. Для постоянной
   регистрации клиента задайте `REA_MCP_HTTP_TOKEN` (≥ 32 символов).
3. Cutter-мост на POSIX слушает Unix-сокет: старый клиент REA не подключится к
   новому мосту и наоборот — обновлять вместе. Путь сокета ≤ 103 байт
   (при длинном `REA_CUTTER_BRIDGE_DIR` мост откажется стартовать с понятной ошибкой).

---

## 2. Оставшиеся проблемы и как их исправить

### 2.1 [Средняя] HTTP-сервер RL-окружений без аутентификации читает локальные файлы и делает исходящие запросы

`src/server/environment/stateIntake.ts:312-341` — метод `data/add` принимает
файловую часть с `uri`: `file://` читается с диска (`readStateFile`), `https://`
скачивается (`downloadState`). Сервер (`rea environment serve`,
`src/server/environment/serveEnvironment.ts:480`) использует тот же
`serveStreamableHttp`, но **без** токена, так что вызвать это может любой
локальный процесс или другой пользователь ОС.

Проверено по коду: документ строго валидируется схемой `rea-state/v1`
(`src/application/environment/environmentStateStore.ts:163`), и только валидный
документ попадает в состояние, которое отдаёт `data/get`. Поэтому содержимое
произвольного файла (например, `~/.docker/config.json`) обратно **не**
возвращается. Остаётся:
- оракул: существует ли файл, читается ли он пользователем REA, JSON ли он и
  JSON-pointer первого расхождения со схемой (`documentError`);
- слепой SSRF: исходящий https-запрос на любой адрес от имени хоста;
- подмена состояния окружения любым локальным процессом (`data/reset`, `data/add`).

Варианты:
- **A (рекомендую).** Передать `bearerToken` и в `serveEnvironment` (тот же код
  уже готов), токен — в карточку окружения/конфиг AgentEnv.
- **B.** Убрать `file://` из сетевого `data/add` (оставить только inline `bytes`);
  чтение файлов — только через CLI.
- **C.** Ограничить `file://` каталогом окружения (allowlist корня) и
  `https://` — allowlist хостов из манифеста окружения.

### 2.2 [Средняя] Тулы, которые запускают сам анализируемый таргет, не закрыты гейтом

`capture_process_scenario`, `observe_native_calls`, `start_gdb_session`,
`start_rizin_debug_session`, `capture_native_ui_scenario`,
`capture_browser_scenario`, `capture_electron_scenario` помечены
`executesForeignCode: true`: они запускают недоверенный бинарник/приложение
с правами пользователя. Это их назначение, поэтому они не включены в гейт, но
prompt injection может инициировать запуск без явного намерения пользователя.

Варианты:
- **A.** Второй уровень гейта `REA_MCP_TARGET_EXECUTION=enabled`.
- **B.** MCP elicitation (подтверждение пользователем) перед каждым запуском таргета.
- **C.** Принудительная песочница (bubblewrap/`sandbox-exec`) для запуска таргетов.

### 2.3 [Средняя] Rizin без `cfg.sandbox` даже после опт-ина

После `REA_MCP_UNRESTRICTED_COMMANDS=enabled` команды идут в Rizin без
песочницы. Варианты: **A.** запускать с `-e cfg.sandbox=true` и отдельной
настройкой для полного режима; **B.** белый список префиксов только для
чтения (`i*`, `af*`, `pd*`, `px*`, `iz*`) — чёрный список (`!`) не годится
из-за обходов `;!`, `` ` ``, `.`, `#!pipe`.

### 2.4 [Средняя] Cutter на Windows остаётся на TCP loopback

Там по-прежнему возможна блокировка 8 слотов локальным процессом (без знания
токена) в фазе ожидания подписанного кадра (до 16 с), и буферизация до
`MAX_FRAME_BYTES` до проверки HMAC. Варианты: **A.** named pipe с DACL текущего
пользователя (в коде уже есть утилиты SDDL); **B.** протокол в два шага —
короткий подписанный заголовок с длиной, затем тело.

### 2.5 [Низкая] Токен HTTP передаётся по plain HTTP

На loopback это приемлемо; при non-loopback bind токен читается из трафика.
Варианты: TLS-терминация (встроенная или через reverse proxy), либо запрет
non-loopback bind без TLS.

### 2.6 [Низкая] Неподписанные ошибки и утечка текста исключений в Cutter-мосте

`bridge/cutter/rea_bridge.py`, `_serve_connection`, ветка `except Exception`:
текст исключения отправляется без подписи, в том числе неаутентифицированному
клиенту. Варианты: до аутентификации — общий `"bad-request"`, после — через
`_send_authenticated`.

### 2.7 Качество кода (не исправлялось, без изменения поведения)

| Проблема | Где | Как исправить |
|---|---|---|
| Неявный контракт через глобальные переменные: 14 × F821, bootstrap генерирует Python-код из TS через `JSON.stringify` | `bridge/hopper_bridge.py`, `src/hopper/BridgeLauncher.ts:681` | Конфиг в JSON-файле + `json.load`; или `runpy.run_path(init_globals=…)` + явная проверка обязательных имён |
| `exec(compile(read()))` вместо импорта (7 мест), мёртвые импорты `json/os/resource/sys` | `bridge/pwntools/*`, `bridge/pwndbg/*` | `runpy.run_path` в том же `try/except MemoryError`; удалить импорты |
| Магические `errno` 12/27 | `bridge/pwntools/layout.py`, `bridge/pwndbg/core_context.py` | `errno.ENOMEM`, `errno.EFBIG` (на macOS числа другие) |
| Цикломатическая сложность: `_dispatch` 68, `inspect_elf` 52, `trace` 37, `project_record` 33 | мосты | Таблица диспетчеризации `dict[str, Callable]`; разбиение по типам/фазам |
| Дословный дубль парсера `REA_BRIDGE_MAX_REQUEST_BYTES` | `hopper_bridge.py` / `cutter/rea_bridge.py` | Общий `bridge/_limits.py` или CI-проверка идентичности |
| Три копии списка заголовков-учётных данных (TS ×2 → теперь ×1, Python ×1) | `CaptureRedaction.ts`, `capture.py` | Генерировать Python-список из TS при сборке или тест на равенство |
| 427 строк > 88 символов, строки по ~400 символов | `bridge/mitmproxy/capture.py:~290` и др. | `ruff format` / разбиение выражений |

---

## 3. Результаты тестов

(заполняется после прогона)
