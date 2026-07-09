# Informe de Seguridad - wordpress.com

**Fecha:** 2026-07-09 12:00:29
**IP:** 192.0.78.17
**Riesgo general:** MEDIO
**WAF:** No detectado

---

## SSL / HTTPS

- **Emisor:** Let's Encrypt
- **Expira:** 2026-10-04
- **Dias restantes:** 87
- **Estado:** OK

---

## Registros DNS

- **SPF:** OK
- **DMARC:** OK
- **MX:** mx-dfw.automattic.com., mx-ams.automattic.com.
- **NS:** ns1.wordpress.com., ns4.wordpress.com., ns2.wordpress.com., ns3.wordpress.com.

---

## Robots.txt y Sitemap

- **robots.txt:** Encontrado
- **sitemap.xml:** Encontrado
- **Rutas interesantes:**   - Disallow: /wp-admin/
  - Allow: /wp-admin/admin-ajax.php
  - Disallow: /wp-login.php
  - Disallow: /remote-login.php
  - Disallow: /public.api/

---

## Cabeceras de Seguridad

### Presentes
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection

### Faltantes
- Content-Security-Policy
- Referrer-Policy
- Permissions-Policy

---

## Puertos Abiertos

- 80/tcp - http
- 443/tcp - https

---

## Subdominios Encontrados

- www.wordpress.com -> 192.0.78.12
- api.wordpress.com -> 192.0.78.12
- mail.wordpress.com -> 192.0.78.12
- admin.wordpress.com -> 192.0.78.13
- dev.wordpress.com -> 192.0.78.13
- staging.wordpress.com -> 192.0.78.13
- app.wordpress.com -> 192.0.78.13
- portal.wordpress.com -> 192.0.78.12
- test.wordpress.com -> 192.0.78.13
- vpn.wordpress.com -> 192.0.78.12

---

## Tecnologias Detectadas

- **web-servers:** Nginx
- **javascript-frameworks:** Lo-dash, Moment.js, React
- **ecommerce:** WooCommerce
- **cms:** WordPress
- **programming-languages:** PHP
- **blogs:** PHP, WordPress

---

*Informe generado automaticamente por domain-checker*
