FROM php:7.4-apache

# Копируем исходники Pass-14 как есть + минимальную обвязку.
COPY . /var/www/html/

# Каталог для загрузок и флаг-файл, доступный только через PHP-код,
# который попадёт в загруженную «картинку-марионетку».
RUN mkdir -p /var/www/html/uploads \
 && printf 'FLAG{upload_pass14_bypass_getimagesize}' > /var/www/html/uploads/.flag \
 && chown -R www-data:www-data /var/www/html/uploads \
 && a2enmod rewrite

EXPOSE 80