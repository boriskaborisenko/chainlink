# PassStore: запуск воркера на DON (CRE)

Этот файл про **деплой на Chainlink DON через CRE CLI**, а не про локальный `tsx --loop`.

## Важно

Текущий `cre/src/workflows/worker.ts` в репозитории — это локальный процесс (Node polling loop).
Его нельзя «как есть» отправить на DON.

Для DON нужен workflow на CRE SDK (Go/TS) с `handler(trigger, callback)`.
Минимально у вас должно быть 2 handler'а:

1. `IssueSdkToken` (trigger: EVM Log `KycRequested`)
2. `SyncKycStatus` (trigger: EVM Log `KycSyncRequested`)

## 1) Preconditions

1. У вас есть Early Access на deploy workflows в CRE.
2. Есть аккаунт в CRE UI: `https://cre.chain.link`.
3. Есть кошелек с ETH в **Ethereum Mainnet** для onchain-регистрации workflow.
4. В `project.yaml` настроен RPC для `ethereum-mainnet`.

Почему mainnet: команды link-key/deploy регистрируют workflow в Workflow Registry onchain.

## 2) Установить CRE CLI

macOS/Linux:

```bash
curl -sSL https://cre.chain.link/install.sh | bash
cre version
```

## 3) Логин и привязка ключа

```bash
cre login
cre whoami
```

В `.env` проекта должен быть `CRE_ETH_PRIVATE_KEY=...`.

Дальше привяжите owner key:

```bash
cre account link-key --owner-label "PassStore Production" --target production-settings
```

Проверка:

```bash
cre account list-key
```

## 4) Проверить конфиг workflow перед деплоем

Проверьте, что:

1. В `workflow.yaml` задан `workflow-name` в `user-workflow` для target (например `production-settings`).
2. Для multi-sig указан `workflow-owner-address`.
3. В target-конфиге есть RPC для `ethereum-mainnet`.

## 5) Залить Sumsub secrets в Vault DON

Создайте файл, например `production-secrets.yaml`:

```yaml
secretsNames:
  SUMSUB_APP_TOKEN:
    - SUMSUB_APP_TOKEN_VALUE
  SUMSUB_SECRET_KEY:
    - SUMSUB_SECRET_KEY_VALUE
```

Задайте значения (через env в shell или `.env`):

```bash
export SUMSUB_APP_TOKEN_VALUE="..."
export SUMSUB_SECRET_KEY_VALUE="..."
```

Залейте secrets:

```bash
cre secrets create production-secrets.yaml --target production-settings
```

Проверка:

```bash
cre secrets list --target production-settings
```

В коде workflow читайте их через `runtime.getSecret({ id: "..." }).result()`.

## 6) Прогнать симуляцию

```bash
cre workflow simulate ./<workflow-folder> --target local-simulation
```

Если нужно реально отправлять onchain write в simulate-режиме:

```bash
cre workflow simulate ./<workflow-folder> --broadcast --target local-simulation
```

## 7) Деплой на DON

```bash
cre workflow deploy ./<workflow-folder> --target production-settings
```

После успешного deploy активируйте:

```bash
cre workflow activate ./<workflow-folder> --target production-settings
```

## 8) Мониторинг

Смотрите executions/logs в CRE UI:

- `https://cre.chain.link/workflows`

Если нужно остановить/удалить:

```bash
cre workflow pause ./<workflow-folder> --target production-settings
cre workflow delete ./<workflow-folder> --target production-settings
```

## 9) Operational notes для PassStore

1. `IssueSdkToken` должен слушать `KycRequested` и писать `storeEncryptedToken(...)`.
2. `SyncKycStatus` должен слушать `KycSyncRequested`, опрашивать Sumsub и писать `attest(...)`/`revoke(...)`.
3. KYC level берите из ENV/secret-конфига workflow, а не из UI как source of truth.
4. Для 404 `Applicant not found` трактуйте как `PENDING`, не как фатальную ошибку.
5. Редкий cron можно оставить только как safety-net, но не как основной UX-триггер.
6. Frontend должен вызывать `requestKycSync()` (например кнопка `Sync + refresh status`) после завершения KYC.

## 10) Быстрый runbook (команды)

```bash
cre whoami
cre account list-key
cre secrets list --target production-settings
cre workflow deploy ./<workflow-folder> --target production-settings
cre workflow activate ./<workflow-folder> --target production-settings
```

---

Официальные страницы:

- CRE overview: https://docs.chain.link/cre
- CLI install: https://docs.chain.link/cre/getting-started/cli-installation/macos-linux
- Deploy workflows: https://docs.chain.link/cre/guides/operations/deploying-workflows
- Workflow commands: https://docs.chain.link/cre/reference/cli/workflow
- Auth commands: https://docs.chain.link/cre/reference/cli/authentication
- Account/link-key: https://docs.chain.link/cre/reference/cli/account
- Secrets (Vault DON): https://docs.chain.link/cre/reference/cli/secrets
- Secrets with deployed workflows: https://docs.chain.link/cre/guides/workflow/secrets/using-secrets-deployed
