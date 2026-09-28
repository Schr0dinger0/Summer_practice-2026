<?php
// Обвязка для изоляции задачи Pass-14.
// Оригинальный config.php из upload-labs здесь не нужен —
// index.php использует только эти две константы.
define('UPLOAD_PATH', __DIR__ . '/uploads');
define('INC_VUL_PATH', '/uploads/.flag');