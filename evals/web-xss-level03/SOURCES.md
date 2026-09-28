# SOURCES

- Источник: https://github.com/The-Cyber-Ledger/TCL-xss-Labs
- Конкретный уровень: Level 03 «Script Tag Blocked»
- Лицензия: MIT
- Исходные файлы, скопированные без изменений:
  - server.js
  - package.json
  - package-lock.json
- Добавленная обвязка (не входит в оригинал):
  - Dockerfile — образ node:18-alpine, npm ci, node server.js
  - compose.yaml — порт 3000, healthcheck на /level/3
- Причина: изоляция задачи, автоматическая проверка готовности.
  Логика фильтрации в /level/3 в server.js сохранена без изменений.
- Примечание о флаге: в оригинале уровня флага нет, успех определялся
  через alert('XSS') в браузере. По требованиям ТЗ добавлен проверяемый
  флаг, который формирует solution.sh после подтверждения обхода фильтра.