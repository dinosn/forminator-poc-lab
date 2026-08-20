# syntax=docker/dockerfile:1

FROM wordpress:cli-php7.4@sha256:946a8b7f237f6cf90d8f04aff952544a0332d43374d598925dcf0180e4441c6c AS wpcli

FROM wordpress:php7.4-apache@sha256:7e46cf3373751b6d62b7a0fc3a7d6686f641a34a2a0eb18947da5375c55fd009

ARG WORDPRESS_VERSION=6.8.3
ARG WORDPRESS_SHA256=92da34c9960e64d1258652c1ef73c517f7e46ac6dfd2dfc75436d3855af46b0c
ARG FORMINATOR_VERSION=1.56.1
ARG FORMINATOR_SHA256=9fc3ec887bba4bcd90be28a82717b04be25dc67bad63222ca35781cf382a603d

RUN set -eux; \
    curl -fL --retry 3 -o /tmp/wordpress.tar.gz "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz"; \
    echo "${WORDPRESS_SHA256}  /tmp/wordpress.tar.gz" | sha256sum -c -; \
    rm -rf /usr/src/wordpress; \
    mkdir -p /usr/src/wordpress; \
    tar -xzf /tmp/wordpress.tar.gz --strip-components=1 -C /usr/src/wordpress; \
    rm /tmp/wordpress.tar.gz; \
    curl -fL --retry 3 -o /opt/forminator.zip "https://downloads.wordpress.org/plugin/forminator.${FORMINATOR_VERSION}.zip"; \
    echo "${FORMINATOR_SHA256}  /opt/forminator.zip" | sha256sum -c -; \
    mkdir -p /usr/src/wordpress/wp-content/mu-plugins /opt/forminator-lab

COPY --from=wpcli /usr/local/bin/wp /usr/local/bin/wp
COPY docker/forminator-lab.php /usr/src/wordpress/wp-content/mu-plugins/forminator-lab.php
COPY docker/setup/ /opt/forminator-lab/

RUN chmod 0755 /usr/local/bin/wp; \
    chown -R www-data:www-data /usr/src/wordpress /opt/forminator.zip /opt/forminator-lab

LABEL org.opencontainers.image.title="Forminator PoC validation lab" \
      org.opencontainers.image.description="Loopback-only WordPress 6.8.3 / PHP 7.4 lab for exact-version Forminator PoC validation" \
      org.opencontainers.image.version="${FORMINATOR_VERSION}"
