ARG PHP_VERSION=8.4.26
FROM php:${PHP_VERSION}-apache

# gdb is used only inside the lab container to capture the crash backtrace of
# the fork-free Apache process (apache2 -X).  Nothing is installed on the host.
RUN apt-get update \
 && apt-get install -y --no-install-recommends gdb \
 && rm -rf /var/lib/apt/lists/*

# build context = project root
COPY config/php-lab.ini /usr/local/etc/php/conf.d/zz-lab.ini

EXPOSE 80
