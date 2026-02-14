# DON_FILES

Структура для реального CRE/DON разделена на 2 независимые реализации:

- `TS/` - TypeScript workflow-пакет под `cre workflow deploy/activate` (DON runtime).
- `GO/` - Go backup worker для локального/резервного запуска той же бизнес-логики.

## Когда использовать что

- Используйте `TS/`, если деплоите в Chainlink DON через CRE workflow CLI.
- Используйте `GO/`, если нужен локальный воркер/резервный рантайм (без DON workflow runtime).

## Быстрые ссылки

- `TS/README.md` - инструкции по DON workflow (secrets, simulate, deploy).
- `GO/README.md` - запуск Go-воркера.
