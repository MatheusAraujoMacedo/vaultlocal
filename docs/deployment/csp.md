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
font-src 'self' https://fonts.gstatic.com;
connect-src 'self';
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
| `font-src` | `'self' https://fonts.gstatic.com` | Fonte Inter via Google Fonts. Se migrarmos para fonte self-hosted, remover a origem externa. |
| `connect-src` | `'self'` | Apenas chamadas same-origin (`/api/*` no `nginx.conf`). Nenhuma telemetria externa. |
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
- **Google Fonts**: vaza somente a origem do request à Google. Para máxima
  privacidade, hospedar Inter localmente (`@fontsource/inter`) e remover
  `fonts.gstatic.com` da CSP.

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
