# Informe de Seguridad - wordpress.com

**Fecha:** 2026-07-10 13:12:41
**IP:** 192.0.78.9
**Riesgo general:** MEDIO
**WAF:** No detectado
**HTTP->HTTPS:** OK - Redirige a HTTPS

---

## SSL / HTTPS

- **Emisor:** Let's Encrypt
- **Expira:** 2026-10-04
- **Dias restantes:** 86
- **Estado:** OK

---

## Informacion Sensible en Codigo Fuente

- EMAIL: privacypolicyupdates@automattic.com
- IP_INTERNA: 10.73.75
- COMENTARIO: <!-- .lp-hero-background.lp-hero-background-plus -->
- COMENTARIO: <!-- wpcom_wp_footer -->
- COMENTARIO: <!-- A8C Analytics [start] -->
- COMENTARIO: <!-- Intentionally left empty -->
- COMENTARIO: <!-- CCPA [start] -->
- TODO: TODO: Identify user via email
				}
				
				/**
				 * Loads and fires the Facebook Pixel.
				 */


---

## CORS

- OK: Sin problemas CORS

---

## Metodos HTTP Peligrosos

- ALERTA: CONNECT habilitado (status 400)

---

## Cookies

- tk_ai: sin HttpOnly flag
- tk_ai_explat: sin HttpOnly flag
- tk_qs: sin HttpOnly flag
- explat_test_aa_weekly_lohp_2026_week_28: sin HttpOnly flag
- wpcom_global_navigation_202606: sin HttpOnly flag

---

## Registros DNS

- **SPF:** OK
- **DMARC:** OK
- **MX:** mx-ams.automattic.com., mx-dfw.automattic.com.

---

## Archivos Sensibles

- Ninguno encontrado

---

## Robots.txt

- **robots.txt:** Encontrado
- INTERESANTE: Disallow: /wp-admin/
- INTERESANTE: Allow: /wp-admin/admin-ajax.php
- INTERESANTE: Disallow: /wp-login.php
- INTERESANTE: Disallow: /remote-login.php
- INTERESANTE: Disallow: /public.api/

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

## Subdominios

- www.wordpress.com -> 192.0.78.13
- api.wordpress.com -> 192.0.78.12
- mail.wordpress.com -> 192.0.78.13
- admin.wordpress.com -> 192.0.78.12
- dev.wordpress.com -> 192.0.78.13
- staging.wordpress.com -> 192.0.78.12
- app.wordpress.com -> 192.0.78.13
- portal.wordpress.com -> 192.0.78.12
- test.wordpress.com -> 192.0.78.12
- vpn.wordpress.com -> 192.0.78.13

---

## Tecnologias

- **web-servers:** Nginx
- **javascript-frameworks:** Lo-dash, Moment.js, React
- **ecommerce:** WooCommerce
- **cms:** WordPress
- **programming-languages:** PHP
- **blogs:** PHP, WordPress

---

*Informe generado automaticamente por domain-checker*
