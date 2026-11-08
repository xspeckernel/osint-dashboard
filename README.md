# TRACE — OSINT Workspace

Dashboard web de OSINT passivo para consulta de **domínios e infraestrutura pública**. Feito com HTML, CSS e JavaScript puro, sem etapa de build.

## Executar

1. Extraia o ZIP.
2. Abra a pasta no VS Code.
3. Inicie um servidor local (recomendado):
   - Python: `python -m http.server 8000`
   - Node: `npx serve .`
4. Acesse `http://localhost:8000`.

Também é possível abrir `index.html` diretamente, mas algumas configurações do navegador podem limitar chamadas externas.

## Recursos

- Validação e normalização de domínio, IP e URL.
- DNS-over-HTTPS via Cloudflare: A, AAAA, MX, NS, TXT e CAA.
- RDAP para dados públicos de registro de domínio e alocação de IP.
- Certificate Transparency via crt.sh.
- Metadados de rede/ASN para IP; o painel não exibe coordenadas nem localização residencial.
- Investigation Graph com relações observadas nos dados públicos retornados.\n- Domain Intelligence: nomes extraídos de Certificate Transparency e verificações SPF/DMARC.\n- Threat Intelligence: atalhos para fontes públicas externas de reputação e contexto.\n- Timeline local de consultas e capturas.\n- Confidence Score de cobertura das fontes (não é probabilidade de precisão).\n- Evidence Center com snapshots locais, exportação JSON e impressão para PDF.\n- Histórico temporário da sessão.
- Anotações persistidas no `localStorage` do navegador.
- Exportação de relatório JSON.
- Layout responsivo para desktop e celular.

## Fontes externas

- `https://cloudflare-dns.com/dns-query`
- `https://rdap.org/`
- `https://crt.sh/`
- `https://ipwho.is/`

A disponibilidade e o CORS dessas fontes podem mudar. Se uma fonte falhar, as demais consultas continuam e o painel informa resultados parciais.

## Limites técnicos

- O projeto é client-side: não possui backend, banco de dados ou autenticação.
- As APIs são públicas e podem aplicar limites, indisponibilidade ou mudanças de formato.
- Anotações ficam no armazenamento local do navegador e não são sincronizadas.
- Não faz port scanning, exploração, brute force, enumeração autenticada ou coleta de dados privados. O Threat Intelligence oferece links para consultas externas; o TRACE não declara reputação sem resultado confirmado.
- Use consultas de infraestrutura em ativos próprios ou para os quais você tenha autorização.

## Estrutura

```text
osint-dashboard/
├── index.html
├── styles.css
├── app.js
└── README.md
```
