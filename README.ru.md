# Polaris

<div align="center">

[简体中文](README.md) · [English](README.en.md) · [繁體中文](README.zh-TW.md) · **Русский** · [فارسی](README.fa.md)

[![release](https://img.shields.io/github/v/release/2outside/Polaris?style=flat-square&color=0E98A4&label=release)](https://github.com/2outside/Polaris/releases/latest)
[![sing-box](https://img.shields.io/badge/sing--box-1.14-0E98A4?style=flat-square)](https://github.com/SagerNet/sing-box)
[![platform](https://img.shields.io/badge/platform-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-0E98A4?style=flat-square)](#установка)
[![license](https://img.shields.io/badge/license-MIT-0E98A4?style=flat-square)](LICENSE)
[![stars](https://img.shields.io/github/stars/2outside/Polaris?style=flat-square&color=0E98A4)](https://github.com/2outside/Polaris/stargazers)

</div>

**Polaris** — кроссплатформенный клиент сетевого прокси на базе sing-box. Tauri 2 (Rust + React).

![Главная](docs/screenshots/home.png)

## Возможности

| Область | Функции |
|---|---|
| Перехват трафика | TUN · Системный прокси · Локальный порт |
| Маршрутизация | Умная / Глобальная / Прямая · Свои правила · Маршрутизация по приложениям · Маршрутизация по регионам (включая возврат в Китай) |
| Протоколы | VLESS · VMess · Trojan · Hysteria 2 / 1 · TUIC · Shadowsocks · AnyTLS · Naive · Snell · SOCKS · HTTP · SSH · Tor · OpenConnect · OpenVPN |
| Сети | WireGuard · Tailscale · WARP; OpenConnect / OpenVPN также относятся сюда, если объявлены внутренние подсети |
| DNS | FakeIP · DoH / DoT · Гонка резолверов · Стратегия IPv6 · Защита от утечек |
| Диагностика | Топология соединений · Логи в реальном времени · Тесты скорости узлов · Проверка доступа к стримингу и ИИ-сервисам |
| Эксплуатация | Управление подписками · Онлайн-обновление ядра · Резервное копирование и восстановление конфигурации · Блокировка приватности · Работа в системном трее |
| Обновление приложения | Стабильный / тестовый каналы · Повторная загрузка текущей версии · Проверка дайджеста установщика |
| Оптимизация памяти | Освобождение основного WebView после 10 минут скрытого или свёрнутого интерфейса; статистика, соединения и логи подписываются по требованию |

<table>
<tr>
<td width="50%"><img src="docs/screenshots/nodes.png" alt="Узлы"><br><sub>Управление узлами и тесты скорости</sub></td>
<td width="50%"><img src="docs/screenshots/rules.png" alt="Правила"><br><sub>Свои правила маршрутизации</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/connections.png" alt="Соединения"><br><sub>Соединения в реальном времени</sub></td>
<td><img src="docs/screenshots/settings.png" alt="Настройки"><br><sub>Настройки</sub></td>
</tr>
</table>

## Установка

Скачайте пакет для своей платформы со страницы [Releases](https://github.com/2outside/Polaris/releases).

| Платформа | Файл |
|---|---|
| macOS | `*-mac-arm64.dmg` / `*-mac-x64.dmg` |
| Windows | `*-win-setup.exe`; портативная сборка — `polaris-portable-*.zip` |
| Linux | `*.deb` / `*.AppImage` |

Пакеты не подписываются платным сертификатом подписи кода, поэтому при первом запуске на каждой платформе требуется ручное разрешение.

Установщик Windows не содержит встроенного WebView2 Runtime; при его отсутствии в системе он загружается из сети. Если у вас урезанная сборка / LTSC или портативная версия без Runtime, сначала установите [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) с сайта Microsoft. Polaris не поставляет офлайн-установщик WebView2.

### Первая установка на macOS

1. Откройте DMG и перетащите `Polaris.app` в «Программы» (Applications). Не запускайте приложение прямо из DMG.
2. Откройте «Терминал» и выполните:

   ```bash
   xattr -cr /Applications/Polaris.app
   ```

3. Запустите Polaris из «Программ». Выполняйте команду один раз после каждой ручной установки или замены из заново скачанного DMG; обновления внутри приложения сами снимают атрибут карантина.

Если Polaris установлен в другом каталоге, замените путь на фактический путь к `.app`. `xattr -cr` рекурсивно очищает расширенные атрибуты этого бандла, поэтому выполняйте её только для пакета Polaris, скачанного из Releases этого репозитория и признанного доверенным. В корне DMG файл `README First.txt` содержит ту же инструкцию на пяти языках. Если система лишь сообщает, что не удалось проверить разработчика, можно вместо этого нажать правой кнопкой на Polaris в Finder → «Открыть» → подтвердить ещё раз.

### Первая установка на Windows

При появлении SmartScreen выберите «Подробнее» → «Выполнить в любом случае».

## Сборка

Требуются Rust stable, Node.js 24+ (в CI сейчас Node 26) и [Tauri CLI 2](https://v2.tauri.app/).

```bash
node scripts/fetch-core.mjs        # загрузка ядра sing-box (закреплено по SHA256)
node scripts/fetch-cronet.mjs      # загрузка libcronet
cargo tauri build --config src-tauri/tauri.linux.conf.json
```

Ядро не хранится в репозитории и должно быть загружено перед сборкой пакета. Платформенный `--config` обязателен: без него получится **пакет без ядра**, причём во время сборки не будет ни одной ошибки — сбой проявится только во время работы. Полное описание, разделение задач в CI и контракт выбора пакета для установщика Windows и обновлятора — в [Сборка и упаковка](docs/build-and-package.en.md).

Проверки разработки:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd ui && npm test
```

## Архитектура

```
ui/          React + Zustand + Vite + Tailwind
src-tauri/   Главный процесс Tauri 2
crates/      17 доменных crate (config-engine / core-supervisor / helper / updater / …)
resources/   Ядро sing-box + libcronet (загружаются при сборке, в репозитории не хранятся)
```

Ядро работает как дочерний процесс-sidecar и управляется через gRPC. TUN и системный прокси обслуживаются привилегированными helper-процессами на всех трёх платформах (macOS / Windows / Linux, целиком на Rust).

## Документация

| Файл | Содержание |
|---|---|
| [docs/build-and-package.en.md](docs/build-and-package.en.md) | Сборка, CI, инварианты упаковки, контракт выбора пакета обновлятором |
| [docs/troubleshooting.ru.md](docs/troubleshooting.ru.md) | Замечания о неподписанных сборках, белый экран / артефакты отрисовки / сбои GPU |

Скриншоты генерируются командой `node scripts/capture-screenshots.mjs`: headless Chrome отрисовывает собранный фронтенд с подставленными тестовыми данными — устанавливать приложение и запускать ядро не нужно.

## Апстрим

| Проект | Назначение |
|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | Прокси-ядро (дочерний процесс-sidecar) |
| [Tauri 2](https://github.com/tauri-apps/tauri) | Десктопная среда выполнения |
| [cronet-go](https://github.com/SagerNet/cronet-go) | libcronet для NaiveProxy |
| [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard) | Встроенная панель |
| [meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) | Наборы правил и гео-данные (`.srs`) |

Авторские права на каждый компонент принадлежат его авторам. Компоненты, интегрированные как подпроцессы или бинарные файлы, перечислены в `NOTICE`; зависимости уровня исходного кода, линкуемые в артефакты (Tauri / React / несколько сотен Rust crate), перечислены по пакетам в `THIRD-PARTY-LICENSES.md`.

## Область применения и отказ от ответственности

Polaris — это универсальный клиент сетевого прокси и инструмент диагностики. Он не предоставляет, не продаёт и не обслуживает прокси-узлы, подписки и сетевые услуги. Используйте его только там, где вы соблюдаете законы и нормативные акты своей юрисдикции, применимые условия обслуживания и правила сети, в которой находитесь, и где у вас есть необходимые разрешения. Запрещается использовать его для несанкционированного доступа, нарушения прав других лиц или иного противоправного злоупотребления. Пользователь сам оценивает надёжность конфигураций, узлов и сторонних ресурсов и отвечает за свои действия и их последствия.

Программное обеспечение предоставляется «как есть», без гарантий доступности сети, анонимности, безопасности, доступа к какому-либо конкретному сервису или целостности данных. Изменения TUN, системного прокси, DNS и маршрутизации могут временно нарушить сетевое соединение; перед важными операциями сделайте резервную копию конфигурации. За исключением случаев, прямо предусмотренных применимым правом, сопровождающие и участники проекта не несут ответственности за прямые или косвенные убытки, возникшие в результате использования или невозможности использования этого ПО. Настоящее уведомление не является юридической или иной профессиональной консультацией.

## Лицензия

MIT (см. `LICENSE`). sing-box (GPLv3) интегрирован как дочерний процесс-sidecar (mere aggregation) и не влияет на лицензию этого проекта; сторонние компоненты перечислены в `NOTICE`.

## История звёзд

<a href="https://www.star-history.com/?repos=2outside%2FPolaris&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&theme=dark&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
    <img alt="Polaris Star History Chart" src="https://api.star-history.com/chart?repos=2outside/Polaris&type=date&legend=top-left&sealed_token=TJg9RA5l3wyd1IgSMMq05QxhNvxS_OcrWbDJxZuwdUwgs-zVIBeoZz2j6swI3y5BxlztkoJMSkkxL6ZbZtw6oyqaRHZSAv0ZS60aVPPuBMdvm8tkxUjyKN1ttiVtPUwJEKObGpBH7BsPhjr6JwFfl_20UYjxgRVOq_V_Q6gKleib6K8LqP3K3nSwPvIJ" />
  </picture>
</a>
