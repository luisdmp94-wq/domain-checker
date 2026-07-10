# Informe de Seguridad - stripchat.com

**Fecha:** 2026-07-10 02:28:57
**IP:** 104.17.117.12
**Riesgo general:** ALTO
**WAF:** [+] The site https://stripchat.com is behind Cloudflare (Cloudflare Inc.) WAF.
**HTTP->HTTPS:** ALERTA - No redirige a HTTPS

---

## SSL / HTTPS

- **Emisor:** Google Trust Services
- **Expira:** 2026-10-07
- **Dias restantes:** 89
- **Estado:** OK

---

## Informacion Sensible en Codigo Fuente

- COMENTARIO: <!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
- COMENTARIO: <!--<![endif]-->
- COMENTARIO: <!-- /.error-footer -->
- COMENTARIO: <!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
- COMENTARIO: <!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css

---

## CORS

- OK: Sin problemas CORS

---

## Metodos HTTP Peligrosos

- ALERTA: CONNECT habilitado (status 400)

---

## Cookies

- __cf_bm: OK

---

## Registros DNS

- **SPF:** OK
- **DMARC:** OK
- **MX:** alt1.aspmx.l.google.com., aspmx5.googlemail.com., aspmx3.googlemail.com., aspmx4.googlemail.com., aspmx.l.google.com., aspmx2.googlemail.com., alt2.aspmx.l.google.com.

---

## Archivos Sensibles

- Ninguno encontrado

---

## Robots.txt

- **robots.txt:** No encontrado


---

## Cabeceras de Seguridad

### Presentes
- Strict-Transport-Security
- X-Frame-Options
- Referrer-Policy

### Faltantes
- Content-Security-Policy
- X-Content-Type-Options
- Permissions-Policy
- X-XSS-Protection

---

## Puertos Abiertos

- 80/tcp - http
- 443/tcp - https
- 8080/tcp - http-proxy
- 8443/tcp - https-alt

---

## Subdominios

- www.stripchat.com -> 104.17.117.12
- api.stripchat.com -> 104.17.117.12
- admin.stripchat.com -> 104.17.118.12
- dev.stripchat.com -> 104.17.117.12
- app.stripchat.com -> 104.17.118.12
- portal.stripchat.com -> 104.17.118.12
- test.stripchat.com -> 104.17.117.12
- vpn.stripchat.com -> 104.17.117.12

---

## Tecnologias

- No detectadas

---

*Informe generado automaticamente por domain-checker*
