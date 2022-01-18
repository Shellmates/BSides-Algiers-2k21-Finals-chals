FROM php:7.0-apache-stretch

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY php/src/ /var/www/html/

RUN mkdir /usr/flag

COPY flag/ /usr/flag/

COPY entrypoint.sh /

RUN chmod +x /entrypoint.sh

WORKDIR /usr/flag/

ENTRYPOINT [ "/entrypoint.sh" ]