# DON_FILES

Шаблонный набор файлов для деплоя PassStore workflows в Chainlink CRE/DON.

## Что внутри

- `project.yaml` - target-конфигурации для CLI (`staging-settings`, `production-settings`).
- `.env.example` - переменные для link-key и CLI-секретов.
- `secrets.production.yaml` - шаблон загрузки Sumsub секретов в DON Vault.
- `workflows/issue-sdk-token/` - workflow для события `KycRequested`.
- `workflows/sync-kyc-status/` - workflow для синка статуса KYC по событию `KycSyncRequested`.
- `scripts/deploy-all.sh` - быстрый runbook-команды.

## Важно

Это **DON-шаблоны**. Их нужно заполнить вашими адресами/chain и дописать бизнес-логику в `main.ts` (там отмечено `TODO`).

Текущий локальный `cre/src/workflows/worker.ts` сюда не переносится 1:1, потому что DON workflow работает через CRE handlers/triggers.

## Быстрый старт

1. Перейдите в `DON_FILES`.
2. Скопируйте `.env.example` -> `.env` и заполните.
3. Обновите `project.yaml` (RPC, owner, target).
4. Обновите `config.production.json` в обоих workflow.
5. Загрузите secrets:

```bash
cre secrets create ./secrets.production.yaml --target production-settings
```

6. Деплой + activate (по каждому workflow):

```bash
cre workflow deploy ./workflows/issue-sdk-token --target production-settings
cre workflow activate ./workflows/issue-sdk-token --target production-settings

cre workflow deploy ./workflows/sync-kyc-status --target production-settings
cre workflow activate ./workflows/sync-kyc-status --target production-settings
```

## Рекомендация

Сначала прогоните каждый workflow через:

```bash
cre workflow simulate ./workflows/<name> --target staging-settings
```
