# Informe de Seguridad - moneybird.com

**Fecha:** 2026-07-10 12:40:46
**IP:** 52.59.144.121
**Riesgo general:** MEDIO
**WAF:** No detectado
**HTTP->HTTPS:** OK - Redirige a HTTPS

---

## SSL / HTTPS

- **Emisor:** Amazon
- **Expira:** 2027-01-05
- **Dias restantes:** 179
- **Estado:** OK

---

## Informacion Sensible en Codigo Fuente

- EMAIL: support@moneybird.com
- COMENTARIO: <!-- Google Tag Manager -->
- COMENTARIO: <!-- Google Tag Manager (noscript) -->
- COMENTARIO: <!-- End Google Tag Manager (noscript) -->
- COMENTARIO: <!-- End Google Tag Manager -->

---

## CORS

- WILDCARD *: https://moneybird.com/
- WILDCARD *: https://moneybird.com/
- WILDCARD *: https://moneybird.com/
- WILDCARD *: https://moneybird.com/

---

## Metodos HTTP Peligrosos

- ALERTA: CONNECT habilitado (status 400)

---

## Cookies

- No se encontraron cookies

---

## Registros DNS

- **SPF:** OK
- **DMARC:** OK
- **MX:** alt2.aspmx.l.google.com., aspmx2.googlemail.com., aspmx3.googlemail.com., aspmx.l.google.com., alt1.aspmx.l.google.com.

---

## Archivos Sensibles

- Ninguno encontrado

---

## Robots.txt

- **robots.txt:** Encontrado
- INTERESANTE: Disallow: /admin/
- INTERESANTE: Disallow: /api/

---

## Cabeceras de Seguridad

### Presentes
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- X-XSS-Protection

### Faltantes
- Content-Security-Policy
- Permissions-Policy

---

## Puertos Abiertos

- 80/tcp - http
- 443/tcp - https

---

## Subdominios

- www.moneybird.com -> 52.59.144.121
- api.moneybird.com -> 18.198.19.182
- admin.moneybird.com -> 52.59.144.121
- dev.moneybird.com -> 52.59.144.121
- staging.moneybird.com -> 52.59.144.121
- app.moneybird.com -> 52.59.144.121
- portal.moneybird.com -> 52.59.144.121
- test.moneybird.com -> 52.59.144.121
- vpn.moneybird.com -> 63.178.33.154

---

## Tecnologias

- **web-servers:** Nginx

---

*Informe generado automaticamente por domain-checker*
