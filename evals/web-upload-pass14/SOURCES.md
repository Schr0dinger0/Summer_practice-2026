# SOURCES

- Источник: https://github.com/c0ny1/upload-labs
- Конкретный уровень: Pass-14
- Лицензия: MIT
- Исходный уровень сложности: средний
- Исходные файлы, скопированные без изменений:
  - index.php
  - helper.php
  - show_code.php
- Добавленная обвязка (не входит в оригинал):
  - Dockerfile — образ php:7.4-apache, создание uploads/, создание .flag
  - compose.yaml — публикация порта 8081 и healthcheck
  - config.php — минимальные константы UPLOAD_PATH и INC_VUL_PATH
  - head.php, menu.php, footer.php — минимальные заглушки
- Причина каждой правки: изоляция задачи, детерминированный флаг,
  отсутствие внешних зависимостей. Логика проверки типа файла в index.php
  сохранена без изменений.