# Informe de Seguridad - moneybird.com

**Fecha:** 2026-07-09 12:11:05
**IP:** 63.178.33.154
**Riesgo general:** MEDIO
**WAF:** No detectado

---

## SSL / HTTPS

- **Emisor:** Amazon
- **Expira:** 2027-01-05
- **Dias restantes:** 180
- **Estado:** OK

---

## Registros DNS

- **SPF:** OK
- **DMARC:** OK
- **MX:** aspmx.l.google.com., aspmx3.googlemail.com., alt2.aspmx.l.google.com., alt1.aspmx.l.google.com., aspmx2.googlemail.com.
- **NS:** ns-1380.awsdns-44.org., ns-1968.awsdns-54.co.uk., ns-766.awsdns-31.net., ns-80.awsdns-10.com.

---

## Archivos Sensibles

- Ninguno encontrado

---

## Robots.txt y Sitemap

- **robots.txt:** Encontrado
- **sitemap.xml:** No encontrado
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

## Subdominios Encontrados

- www.moneybird.com -> 51.102.218.191
- api.moneybird.com -> 63.186.33.7
- admin.moneybird.com -> 51.102.218.191
- dev.moneybird.com -> 63.186.33.7
- staging.moneybird.com -> 63.178.33.154
- app.moneybird.com -> 63.178.33.154
- portal.moneybird.com -> 63.186.33.7
- test.moneybird.com -> 51.102.218.191
- vpn.moneybird.com -> 51.102.218.191

---

## Tecnologias Detectadas

- **web-servers:** Nginx

---

*Informe generado automaticamente por domain-checker*
