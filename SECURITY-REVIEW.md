# Ревью безопасности и качества кода форка `ArMikhaylov/nrea`

База: `morluto/rea` @ `64196b0` (v6.8.0). Раунд 1 — ветка `security-hardening` (вмержена, PR #1), раунд 2 — `security-hardening-2`.

Область ревью: Python-мосты (`bridge/**/*.py`, ~4.5k строк, построчно + `ruff`),
MCP-транспорт (stdio/HTTP), тулы с произвольными командами, распаковка
архивов, редактирование захваченного трафика, HTTP-сервер RL-окружений.
Не покрыто: ~170k строк парсеров форматов в `src/domain` (нужен фаззинг),
`setup`/`update`, Frida-агент, браузерная автоматизация целиком.

---

## 1. Раунд 1: что исправлено

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

## 2. Раунд 2 (ветка `security-hardening-2`): оставшиеся находки

| # | Проблема | Статус |
|---|---|---|
| 2.1 | HTTP-сервер RL-окружений без аутентификации читал `file://` и скачивал `https://` по запросу клиента (оракул существования/формата файлов, слепой SSRF, подмена состояния) | **Исправлено**: `file://` и `https://` выключены по умолчанию; `REA_ENVIRONMENT_STATE_ROOT` разрешает чтение только внутри каталога (с проверкой symlink, путь вне корня отклоняется одинаково, есть файл или нет); `REA_ENVIRONMENT_STATE_HTTPS=enabled` разрешает загрузку; `REA_MCP_HTTP_TOKEN` включает bearer-аутентификацию; без токена — предупреждение в логе. Dockerfile бандла явно включает оба вида uri, чтобы изолированный контейнер сохранил контракт AgentEnv |
| 2.2 | Тулы, запускающие сам таргет, не были закрыты гейтом | **Исправлено**: `REA_MCP_TARGET_EXECUTION=enabled`. Список выводится из аннотации `executesForeignCode` (новый тул с этим эффектом попадает под гейт автоматически); `close_*` никогда не блокируются. Сейчас это `capture_process_scenario`, `observe_native_calls`, `start_rizin_debug_session`, `resume_frida_session`, `capture_native_ui_scenario`, `capture_browser_scenario`, `capture_electron_scenario` |
| 2.3 | Rizin без песочницы | **Исправлено**: one-shot `execute_rizin_command` идёт с `-e cfg.sandbox=true` до `-c`; отключение — `REA_RIZIN_SANDBOX=disabled`. **Не проверено на реальном Rizin** (запуск бинарника в среде ревью был запрещён) — проверьте `rizin -e cfg.sandbox=true -c '!id' /bin/true` |
| 2.4 | Cutter на Windows остаётся на TCP loopback | **Не исправлено, осознанно** — см. 3.1 |
| 2.5 | Bearer-токен по plain HTTP на не-loopback адресе | **Исправлено**: `rea mcp --http` отказывается слушать вне loopback без `REA_MCP_HTTP_INSECURE_NETWORK=enabled` (ошибка `host_allowlist`/`insecure_transport` с рекомендацией TLS-прокси) |
| 2.6 | Cutter-мост отдавал текст исключений неаутентифицированным клиентам и неподписанные ошибки аутентифицированным | **Исправлено**: до аутентификации — только фиксированные коды (`bad-request`, `frame-limit-exceeded`); после — подписанный ответ `bridge-exception` |
| 2.7 | Качество Python-мостов | **Частично**, см. ниже |

### 2.7 Качество кода — что сделано

- **Hopper-мост:** 14 неявных глобальных имён (F821) заменены на `_bootstrap(name)`
  с понятной ошибкой; при запуске все обязательные значения проверяются до
  работы. `_dispatch` (цикломатическая сложность 68) переписан в таблицу
  `_SESSION_OPERATIONS` / `_DOCUMENT_OPERATIONS`; набор из 39 методов сверен со
  старой версией один к одному. Неизвестный метод теперь сразу получает
  `Unknown bridge method`, без попытки найти документ.
- **pwntools/pwndbg:** `exec(compile(open(...)))` → `runpy.run_path` (импорт
  невозможен: `python -I` не кладёт каталог скрипта в `sys.path`); `errno.ENOMEM`
  и `errno.EFBIG` вместо 12/27; удалены мёртвые импорты; `del` вместо
  присваивания `None` для освобождения резерва памяти. Механика обёрток
  проверена на подставных impl-файлах: `MemoryError` → 75/`M` (в том числе при
  реальной ошибке выделения), `EFBIG` → 76/`F`.
- **Дубли:** `tests/conformance/bridgeSharedSources.test.ts` фиксирует
  идентичность парсера `REA_BRIDGE_MAX_REQUEST_BYTES` в двух мостах и списка
  заголовков-учётных данных в TS (`CAPTURE_CREDENTIAL_HEADERS`) и
  `capture.py`.
- **Форматирование:** `ruff format` для `capture.py`, `layout_impl.py`,
  `recorded_crash_impl.py`, `core_context.py`, `decoder_runtime.py`; AST до и после
  совпадает. `ruff --select F,E9,B` по `bridge/` — чисто (было 21 ошибка).

## 3. Что остаётся и почему

### 3.1 Cutter-мост на Windows (TCP loopback)
Локальный процесс может занять 8 слотов (hello не требует секрета, затем до 16 с
ожидания подписанного кадра) — это **DoS моста, без утечки и выполнения кода**.
Настоящее исправление — named pipe с DACL текущего пользователя (в коде уже
есть утилиты SDDL). Не сделано: это заметный объём Windows-специфичного кода,
который нельзя было запустить и протестировать в среде ревью, а правила
репозитория требуют не наращивать сложность без согласования.
Варианты: **A** named pipe; **B** двухшаговый протокол (короткий подписанный
заголовок с длиной до чтения тела) — сокращает удержание слота с ~16 с до ~1 с,
но DoS не устраняет.

### 3.2 Сложные функции без тестового окружения
`inspect_elf` (CC 52, pwntools), `trace` (CC 37, LLDB), `project_record` (CC 33,
mitmproxy) не рефакторились: их тесты требуют pwntools 4.15.0, LLDB и
mitmproxy 12.2.3, которых нет в среде. Рефакторить вслепую — риск регрессий в
коде, работающем с недоверенными данными.

### 3.3 Прочее
- Bootstrap Hopper по-прежнему собирается из TS через `JSON.stringify` → Python-
  литерал. Это корректно (строковый литерал JSON — подмножество Python), но
  надёжнее передавать JSON-файл; сейчас контракт хотя бы явно проверяется.
- `rea environment serve` без `REA_MCP_HTTP_TOKEN` остаётся без аутентификации
  ради совместимости с AgentEnv; опасные возможности (`file://`, `https://`)
  при этом выключены по умолчанию.
- Остальные замечания ruff (E501 в длинных строковых литералах, PLR2004, SIM105)
  — косметика.

### Breaking changes раунда 2

1. MCP-тулы запуска таргета отклоняются без `REA_MCP_TARGET_EXECUTION=enabled`.
2. `rea environment serve` на хосте не принимает `file://`/`https://` без
   `REA_ENVIRONMENT_STATE_ROOT` / `REA_ENVIRONMENT_STATE_HTTPS=enabled`
   (Docker-бандл включает их сам).
3. `rea mcp --http` на не-loopback адресе требует `REA_MCP_HTTP_INSECURE_NETWORK=enabled`.
4. One-shot Rizin-команды идут в `cfg.sandbox`; `!`-команды не работают без
   `REA_RIZIN_SANDBOX=disabled`.

## 4. Результаты тестов (раунд 1)

Окружение: Linux x64, Node.js 24.22.1, Python 3.13. Всё запускалось локально
(`npm run test:focused`), CI форка не запускался.

| Набор | Результат |
|---|---|
| `tsc --noEmit` (весь проект) | без ошибок |
| `npm run docs:check` | пройден |
| Гейт + MCP-тесты тулов Rizin/GDB/Cutter/Frida + HTTP-транспорт (`rea mcp --http` как процесс) — 19 файлов | 176/176 после правки тестов (см. ниже) |
| Cutter: TS-клиент и реальный Python-мост в serve-режиме — 14 файлов | 223/223 |
| `tests/fixtures/cutter_bridge_protocol_test.py` | 33/33 |
| Захват трафика (HAR, SAZ, qlog, protobuf, Playwright, редактирование) — 16 файлов | 353 passed, 3 skipped |
| Сборка RL-окружений + snapshot replay — 4 файла | 55 passed, 1 skipped |
| `npm audit` (prod + dev) | 0 уязвимостей |

Существующие тесты, которые вызывают закрытые тулы через MCP, теперь явно
включают `REA_MCP_UNRESTRICTED_COMMANDS=enabled` (через `environment` у
`createServer` или `server.unrestrictedCommandsEnabled = true`). Сам отказ по
умолчанию проверяет `tests/boundary/mcp/unrestrictedCommandsGate.test.ts`.

Не запускалось:
- полный набор (`npm run check:pr`): 855k строк тестов, много часов на 4 ядрах;
- `bridge/mitmproxy/test_capture.py`: в окружении нет закреплённого mitmproxy 12.2.3;
- реальный Cutter/Hopper/IDA, Windows-ветки (named pipe/TCP-мост Cutter, проверка
  имён устройств — только через симуляцию `platform = "win32"`).

`ruff` по `bridge/`: 611 → 614 замечаний (+3 — длинные строки и
magic-number в новых тестах), новых F/B/E9 нет.
