# Спецификация B34: Двухконтурная оценка угроз (Dual-Track Perimeter Assessment) и внешние манифесты развёртывания (Helm/K8s/GitOps)

**Дата:** 5 октября 2026 г.  
**Статус:** Согласовано с пользователем (Design Approved)  
**Область:** `internal/domain`, `internal/exposure`, `internal/evaluator`, `internal/report`, `cmd/izyan`  
**Канонический бэклог:** `docs/dev/gap-analysis.md` (пункт B34)

---

## 1. Проблема и мотивация

В текущей архитектуре анализатора `izyan`:
1. Модель сетевого доверия к исходящим подключениям (пирам) регулируется бинарным флагом CLI `--trusted-peer`.
2. Если флаг не передан (поведение по умолчанию), анализатор применяет максимально консервативную модель угроз — **Zero Trust / Hostile Peer** (любой сетевой пир, включая брокеры сообщений или внутренние RPC-сервисы, рассматривается как потенциально враждебный).
3. В результате на реальных монорепозиториях (таких как микросервисы интеграционных шин) уязвимости клиентских сетевых протоколов (например, RabbitMQ `amqp091-go`: `GHSA-6c5v`, `GHSA-xwwf`, `GHSA-j497`) зависают в статусе `INCONCLUSIVE`. Причина: статический анализатор кода Go не может доказать, что внешний брокер физически не пришлёт некорректный байт по сети.
4. При этом в промышленной корпоративной среде RabbitMQ развёрнут во внутреннем закрытом контуре (Kubernetes ClusterIP / Service Mesh / Istio / приватный VPC), и внешний злоумышленник не имеет к нему прямого доступа.
5. Чтобы получить опровержение (`NO_EXPLOIT_PATH_FOUND / DISMISSED`), сейчас от человека требуется:
   - Вручную исследовать сетевую топологию каждого сервиса перед каждым запуском;
   - Запускать инструмент с дополнительными специфическими флагами.
6. Это противоречит концепции полностью автономного SAST/SCA анализатора. Более того, в корпорациях манифесты развёртывания (Helm-чарты, ArgoCD GitOps, K8s YAML) часто хранятся в **отдельных репозиториях** или поставляются в виде упакованных **архивов (`.tgz`, `.tar.gz`, `.zip`)**, а не лежат в корне репозитория кода.

---

## 2. Архитектурное решение

Решение строится на трёх ключевых принципах:
1. **Параллельная двухконтурная оценка угроз (Dual-Track Assessment):** инструмент в рамках одного прогона всегда рассчитывает статус уязвимости по двум независимым профилям угроз (Zero Trust vs Cluster Perimeter).
2. **Универсальный приёмник манифестов развёртывания:** поддержка локальных путей, внешних GitOps-директорий и упакованных архивов чартов (`.tgz`, `.zip`).
3. **Автоматический выбор фактического профиля (Auto-Detection):** при наличии доказательств кластерной изоляции целевой вердикт продукта автоматически становится `NO_EXPLOIT_PATH_FOUND (DISMISSED)`, снимая необходимость ручной настройки.

---

## 3. Детальный дизайн компонентов

### 3.1. Доменная модель (`internal/domain/domain.go`)

В доменную модель добавляется представление профилей угроз и их вердиктов:

```go
// ThreatProfile определяет модель сетевого доверия к пирам.
type ThreatProfile string

const (
    // ProfileZeroTrust — модель наихудшего сценария: брокер/пир может быть
    // скомпрометирован или доступен внешнему злоумышленнику.
    ProfileZeroTrust ThreatProfile = "zero_trust"

    // ProfileClusterPerimeter — модель доверенной инфраструктуры: сервис
    // взаимодействует с пирами строго внутри защищённого контура
    // (K8s ClusterIP / Istio Mesh / приватная сеть).
    ProfileClusterPerimeter ThreatProfile = "cluster_perimeter"
)

// ProfileVerdict содержит оценку уязвимости для конкретного профиля угроз.
type ProfileVerdict struct {
    Profile        ThreatProfile  `json:"profile"`
    Title          string         `json:"title"`                    // "Внутренний кластер (Mesh / ClusterIP)"
    Verdict        Verdict        `json:"verdict"`                  // NO_EXPLOIT_PATH_FOUND / INCONCLUSIVE / EXPLOITABLE
    Reason         string         `json:"reason"`                   // Текстовое обоснование вердикта
    Falsifier      FalsifierKind  `json:"falsifier,omitempty"`      // Например, "trusted-infrastructure"
    Priority       TriagePriority `json:"priority"`                 // DISMISSED / P0 / P1 / P2
    SLA            string         `json:"sla"`                      // "None" / "24h" / "7 days"
    IsTargetActual bool           `json:"is_target_actual"`        // Является ли профиль фактическим по детекции среды
}

// В AnalysisCase расширяется контекст периметра (обратная совместимость через omitempty):
type AnalysisCase struct {
    // ... существующие поля ...
    DetectedPerimeter string           `json:"detected_perimeter,omitempty"`  // "cluster-internal" | "public" | "unknown"
    PerimeterRationale string          `json:"perimeter_rationale,omitempty"`  // Обоснование детекции со ссылкой на evidence
    Profiles          []ProfileVerdict `json:"profiles,omitempty"`             // Сводная матрица двух контуров
}
```

### 3.2. Универсальный сканер манифестов (`internal/exposure/deploy.go`)

Расширяем `ScanDeploy` для поддержки внешних источников и архивов:

```go
// DeployScanOptions задаёт параметры поиска и распаковки манифестов.
type DeployScanOptions struct {
    RootPath    string   // Корневая директория репозитория продукта
    ExtraPaths  []string // Дополнительные пути (--deploy-manifests: папки, репозитории GitOps)
    ArchivePath string   // Путь к архиву чарта (.tgz, .tar.gz, .zip)
}

func ScanDeployWithOptions(opts DeployScanOptions) ([]domain.ExposureFact, error)
```

1. **Распаковка архивов (in-memory / temp dir):**
   - Если передан `.tgz` или `.tar.gz`: потоковое чтение через `archive/tar` + `compress/gzip`.
   - Если передан `.zip`: чтение через `archive/zip`.
   - Фильтрация: извлекаются только файлы `.yaml` / `.yml` (не более 1 МБ), исключая бинарники и посторонние файлы.
2. **Эвристический автопоиск (Auto-Discovery):**
   - Если явный путь не передан, сканер ищет:
     - Локальные каталоги: `deploy/`, `helm/`, `k8s/`, `manifests/`, `infra/`, `charts/`;
     - Локальные архивы чартов: файлы `*.tgz`, `*.zip` в корне репозитория;
     - Соседние каталоги на том же уровне файловой системы: `../<repo>-deploy`, `../<repo>-helm`, `../<repo>-infra`.

### 3.3. Детекция кластерной изоляции (`detectClusterPerimeter`)

На основе собранных `domain.ExposureFact`:
1. **Признаки изолированного контура (`cluster-internal`):**
   - Все найденные K8s Service имеют тип `ClusterIP` (или тип не указан, что в K8s дефолтится в `ClusterIP`);
   - Сетевые слушатели привязаны к `127.0.0.1`, `localhost` или `unix`;
   - Присутствуют Istio `AuthorizationPolicy` / `RequestAuthentication` или sidecar injection;
   - **Отсутствуют** публичные шлюзы (`Ingress`, `Gateway`, `VirtualService` с публичным хостом, `Route`, `LoadBalancer`, `NodePort`).
2. **Результат детекции:**
   - Если признак кластера подтверждён: `DetectedPerimeter = "cluster-internal"`, формируется Evidence `EV-PERIMETER-CLUSTER`.
   - Если обнаружен публичный шлюз / порт `0.0.0.0`: `DetectedPerimeter = "public"`.
   - Если манифесты не найдены: `DetectedPerimeter = "unknown"`.

### 3.4. Двухконтурный движок оценки (Dual-Track Evaluation)

При формировании итогового отчёта:
1. **Прогон 1: Zero Trust (`TrustedPeer = false`):**
   - Брокерные условия `C-PEER-INPUT` оцениваются строго без доверия.
   - Формируется `ProfileVerdict` для `zero_trust`.
2. **Прогон 2: Cluster Perimeter (`TrustedPeer = true`):**
   - Брокерные условия `C-PEER-INPUT` получают статус `NegativeVerified` с фальсификатором `FalsifierTrustedInfrastructure`.
   - Формируется `ProfileVerdict` для `cluster_perimeter` (вердикт: `NO_EXPLOIT_PATH_FOUND`, приоритет: `DISMISSED`).
3. **Резолюция целевого вердикта (`c.Verdict`):**
   - Если `DetectedPerimeter == "cluster-internal"`:
     - Целевой профиль — **Cluster Perimeter**.
     - Поле `c.Verdict` принимает вердикт кластерного контура (`NO_EXPLOIT_PATH_FOUND`).
     - Флаг `IsTargetActual = true` выставляется для профиля `cluster_perimeter`.
   - Если `DetectedPerimeter == "public"` или `"unknown"`:
     - Целевой профиль — **Zero Trust**.
     - Флаг `IsTargetActual = true` выставляется для профиля `zero_trust`.
   - В массиве `c.Profiles` сохраняются оба профиля, обеспечивая полную прозрачность.

### 3.5. Отчётность (`report.md`, `report.json`, CLI)

В самом начале `report.md` (в секции `## Резюме`) рендерится структурированная матрица:

```markdown
## Резюме безопасности и двухконтурная оценка

- **Обнаруженный периметр развёртывания:** `Внутренний кластер (Kubernetes ClusterIP / Istio)`
- **Обоснование периметра:** `helm/templates/service.yaml: Service type ClusterIP, отсутствие публичного Ingress`
- **Итоговый вердикт окружения:** 🟢 **NO_EXPLOIT_PATH_FOUND** (Угроза нейтрализована сетевым периметром)
- **Приоритет триажа:** **DISMISSED** (Снято с повестки, блокировка сборки отсутствует)

### Матрица сетевых периметров угроз

| Сетевой контур | Модель угроз | Вердикт анализатора | Приоритет триажа | Действие для команды |
|---|---|---|---|---|
| **Внутренний кластер / Mesh** *(Фактический)* | Доверенная инфраструктура | 🟢 **NO_EXPLOIT_PATH_FOUND** | **DISMISSED** | **Действий не требуется:** сервис и зависимости изолированы в контуре. |
| **Публичный интернет** | Zero Trust / Hostile Peer | 🟡 **INCONCLUSIVE** | **P1 / 7 days** | **Внимание:** при выносе сервиса за пределы кластера потребуется аудит. |
```

---

## 4. Контракты интерфейсов (CLI и ENV)

1. **CLI флаги:**
   - `--deploy-manifests <path>`: путь к внешнему каталогу манифестов или архиву (`.tgz`, `.tar.gz`, `.zip`).
   - `--perimeter <auto|cluster|public>`: принудительное переопределение контекста (по умолчанию `auto`).
2. **Переменные окружения:**
   - `VA_DEPLOY_MANIFESTS`: путь к манифестам или архиву.
   - `VA_PERIMETER`: режим периметра.

---

## 5. План валидации и тестов

1. **Unit-тесты сканера архивов (`internal/exposure/deploy_archive_test.go`):**
   - Сканирование упакованного Helm-чарта `.tgz` с извлечением `ClusterIP`;
   - Сканирование архива `.zip` с `VirtualService` и `AuthorizationPolicy`;
   - Изоляция от некорректных путей / path traversal (Zip Slip protection).
2. **Unit-тесты детекции периметра (`internal/exposure/perimeter_test.go`):**
   - Набор фактов только с `ClusterIP` -> `cluster-internal`;
   - Набор фактов с `Ingress` / `0.0.0.0` -> `public`;
   - Пустой набор фактов -> `unknown`.
3. **Unit-тесты двухконтурного движка (`internal/report/dual_track_test.go`):**
   - Проверка генерации `c.Profiles` с корректными вердиктами и приоритетами;
   - Проверка рендеринга матрицы в Markdown на русском и английском языках.
4. **Регрессионная валидация:**
   - Автономный запуск на `eval/corpus-real.json` (38 кейсов) — сохранение инварианта `false-safe = 0`;
   - Запуск на `eval/live-corpus.json` (live-микросервис интеграции) с указанием Helm-манифестов сервиса — проверка автоматического перехода 4 брокерных кейсов в `DISMISSED`.
