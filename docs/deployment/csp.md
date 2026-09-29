# Content Security Policy (CSP)

Documento de referência para a CSP servida pelo Nginx em produção/Docker.

## Por que CSP existe aqui

O VaultLocal é local-first, mas ainda é uma SPA exposta a scripts em
extensões de navegador, bookmarklets e (em futuros deploys LAN) proxies
intermediários. Uma CSP restritiva elimina classes inteiras de ataque
(XSS, data exfiltration, clickjacking) sem custo de runtime.

## Política atual

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self' https://api.pwnedpasswords.com;
base-uri 'none';
object-src 'none';
form-action 'self';
frame-ancestors 'none';
```

Definida em `frontend/nginx.conf` via `add_header Content-Security-Policy`.

## Justificativa por diretiva

| Diretiva | Valor | Motivo |
|---|---|---|
| `default-src` | `'self'` | Bloqueia tudo por padrão; abrimos só o necessário. |
| `script-src` | `'self' 'wasm-unsafe-eval'` | `hash-wasm` (Argon2id) precisa de `WebAssembly.compile()`. `'wasm-unsafe-eval'` é específico para WASM e **não** habilita `eval()` em JS. Nunca usar `'unsafe-eval'` genérico. |
| `style-src` | `'self' 'unsafe-inline'` | Tailwind aplica styles inline via `style="..."` em alguns componentes. Ideal: migrar para nonce/hash; mantido inline por simplicidade no MVP. |
| `img-src` | `'self' data:` | `data:` necessário para o QR code do TOTP gerado por `qrcode.toDataURL()`. |
| `font-src` | `'self'` | O frontend não depende mais de fontes externas. |
| `connect-src` | `'self' https://api.pwnedpasswords.com` | API local e consulta opcional ao HIBP online; o navegador envia apenas o prefixo de 5 caracteres. |
| `base-uri` | `'none'` | Impede alteração da base URL por HTML injetado. |
| `object-src` | `'none'` | Desativa plugins/objetos que o cofre não precisa. |
| `form-action` | `'self'` | Restringe destinos de submissão de formulários. |
| `frame-ancestors` | `'none'` | Clickjacking defense (par com `X-Frame-Options: DENY`). |

## Outros headers de segurança (mesmo bloco)

- `X-Frame-Options: DENY` — fallback para browsers antigos.
- `X-Content-Type-Options: nosniff` — impede MIME sniffing.
- `Referrer-Policy: no-referrer` — não vaza URLs em requests externos.
- `Permissions-Policy: camera=(), microphone=(), geolocation=()` — desliga
  APIs que o cofre nunca precisa.

## Trade-offs aceitos

- **WASM com `'wasm-unsafe-eval'`**: necessário para Argon2id. Se um dia
  migrarmos para `argon2` nativo via FFI ou WebCrypto com
  `deriveBits`+PBKDF2 (mais fraco), podemos remover.
- **`'unsafe-inline'` em styles**: Tailwind inline em classes utilitárias
  é falso-positivo comum; aceito por ora. Alternativa futura: build com
  hash/nonce por tag.
- **Fontes externas**: não são usadas pelo frontend atual; manter essa
  decisão reduz dependências e requests de terceiros.

## O que mudaria em deploy público (Render/SaaS)

- Adicionar `upgrade-insecure-requests`, `block-all-mixed-content`.
- Trocar `script-src 'self'` para incluir hashes específicos por script
  (evitar `'wasm-unsafe-eval'` junto a `'unsafe-inline'` — hoje não temos).
- Considerar `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`,
  `Cross-Origin-Resource-Policy` se habilitarmos WebAuthn de forma ampla.

## Como auditar

```bash
curl -sI http://127.0.0.1:8080/ | grep -i content-security
```

e no browser aberto: DevTools → Console não deve reportar `Refused to load`
nem `violates the following Content Security Policy directive`.
