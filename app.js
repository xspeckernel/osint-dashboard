/* TRACE OSINT Workspace — consultas passivas a fontes públicas. */
"use strict";

const $ = (selector) => document.querySelector(selector);
const state = {
  target: null, dns: [], certs: [], rdap: null, ipInfo: null,
  runs: 0, history: [], notes: JSON.parse(localStorage.getItem("trace_notes") || "[]"),
  timeline: JSON.parse(localStorage.getItem("trace_timeline") || "[]"),
  evidence: JSON.parse(localStorage.getItem("trace_evidence") || "[]"),
  mailSecurity: null, emailAudit: null
};
const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"];
const API = {
  dns: (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  rdapDomain: (name) => `https://rdap.org/domain/${encodeURIComponent(name)}`,
  rdapIp: (ip) => `https://rdap.org/ip/${encodeURIComponent(ip)}`,
  certs: (name) => `https://crt.sh/?q=${encodeURIComponent("%." + name)}&output=json`,
  ip: (ip) => `https://ipwho.is/${encodeURIComponent(ip)}`
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
}
function showToast(message) {
  const el = $("#toast"); el.textContent = message; el.classList.add("show");
  clearTimeout(showToast.timer); showToast.timer = setTimeout(() => el.classList.remove("show"), 2600);
}
function setAlert(message) {
  const el = $("#alertBox");
  if (!message) { el.classList.add("hidden"); el.textContent = ""; return; }
  el.textContent = message; el.classList.remove("hidden");
}
function normalizeTarget(raw) {
  let value = raw.trim();
  if (!value) throw new Error("Digite um domínio, endereço IP ou URL.");
  if (/^https?:\/\//i.test(value)) {
    const url = new URL(value);
    value = url.hostname;
  } else if (value.includes("/") || value.includes("@") || value.includes(" ")) {
    throw new Error("Formato inválido. Informe somente um domínio, IP ou URL completa.");
  }
  value = value.replace(/\.$/, "").toLowerCase();
  const isIPv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value);
  const isIPv6 = value.includes(":") && /^[0-9a-f:]+$/i.test(value);
  if (isIPv4 || isIPv6) return { value, type: "IP" };
  if (value.length > 253 || !value.includes(".") ||
      !value.split(".").every(label => label.length > 0 && label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
    throw new Error("Domínio inválido. Exemplo: exemplo.com");
  }
  return { value, type: "DOMAIN" };
}
async function fetchJson(url, options = {}, timeout = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); }
}
function formatDate(value) {
  if (!value) return "Não informado";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("pt-BR");
}
function addHistory(target) {
  state.history = [{ target: target.value, type: target.type, at: new Date() }, ...state.history].slice(0, 5);
  renderHistory();
}
function renderHistory() {
  const el = $("#historyList");
  el.innerHTML = state.history.length ? state.history.map(item =>
    `<div class="history-item"><b>${escapeHtml(item.target)}</b><small>${item.type} · ${item.at.toLocaleTimeString("pt-BR",{hour:"2-digit",minute:"2-digit"})}</small></div>`
  ).join("") : '<div class="compact-empty">Seu histórico aparecerá aqui.</div>';
}
function updateTargetHeader() {
  $("#targetName").textContent = state.target?.value || "Nenhum alvo selecionado";
  $("#targetType").textContent = state.target ? state.target.type : "AGUARDANDO CONSULTA";
  $("#targetTime").textContent = state.target ? new Date().toLocaleString("pt-BR") : "—";
  $("#statRuns").textContent = state.runs;
}
function renderOverview() {
  const target = state.target;
  const el = $("#overviewContent");
  if (!target) return;
  if (target.type === "IP") {
    const ip = state.ipInfo || {};
    const rdap = state.rdap || {};
    el.innerHTML = `<div class="overview-grid">
      ${tile("ENDEREÇO IP", target.value)}
      ${tile("ASN", ip.connection?.asn ? `AS${ip.connection.asn}` : "Não disponível")}
      ${tile("ORGANIZAÇÃO", ip.connection?.org || ip.connection?.isp || "Não disponível")}
      ${tile("PAÍS", ip.country_code || "Não disponível")}
      ${tile("TIPO DE CONEXÃO", ip.connection?.type || "Não disponível")}
      ${tile("REDE / CIDR", rdap?.handle || "Consulte RDAP")}
    </div>`;
    return;
  }
  const dnsCount = state.dns.filter(x => x.Answer?.length).length;
  const nameservers = state.rdap?.nameservers?.map(n => n.ldhName).filter(Boolean).join(", ") || "Não disponível";
  const created = state.rdap?.events?.find(e => e.eventAction === "registration")?.eventDate;
  el.innerHTML = `<div class="overview-grid">
    ${tile("DOMÍNIO", target.value)}
    ${tile("TIPOS DNS COM RESPOSTA", `${dnsCount} / ${DNS_TYPES.length}`)}
    ${tile("CERTIFICADOS PÚBLICOS", state.certs.length)}
    ${tile("REGISTRO", state.rdap ? "RDAP consultado" : "Indisponível")}
    ${tile("CRIADO EM", formatDate(created))}
    ${tile("NAMESERVERS", nameservers)}
  </div>`;
}
function tile(label, value) {
  return `<div class="data-tile"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`;
}
function renderRdap() {
  const el = $("#rdapSummary");
  if (!state.rdap) { el.textContent = "Nenhum registro carregado."; return; }
  const data = state.rdap;
  const registrar = data.entities?.flatMap(e => e.vcardArray?.[1] || [])
    .find(row => row[0] === "fn")?.[3] || "Não identificado";
  const created = data.events?.find(e => e.eventAction === "registration")?.eventDate;
  const expires = data.events?.find(e => e.eventAction === "expiration")?.eventDate;
  el.innerHTML = `<div class="data-tile"><span>REGISTRAR / ENTIDADE</span><b>${escapeHtml(registrar)}</b></div>
    <div class="data-tile" style="margin-top:8px"><span>REGISTRO CRIADO</span><b>${escapeHtml(formatDate(created))}</b></div>
    <div class="data-tile" style="margin-top:8px"><span>EXPIRAÇÃO</span><b>${escapeHtml(formatDate(expires))}</b></div>`;
}
function renderDns() {
  const records = state.dns.flatMap(result => (result.Answer || []).map(answer => ({
    type: result.typeName || result.qtype, name: answer.name, ttl: answer.TTL, data: answer.data
  })));
  $("#dnsCount").textContent = `${records.length} REGISTROS`;
  $("#statDns").textContent = records.length;
  $("#dnsResults").innerHTML = records.length ? `<table><thead><tr><th>TIPO</th><th>NOME</th><th>TTL</th><th>RESPOSTA</th></tr></thead><tbody>${records.map(r =>
    `<tr><td><span class="record-type">${escapeHtml(r.type)}</span></td><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.ttl)}</td><td>${escapeHtml(r.data)}</td></tr>`
  ).join("")}</tbody></table>` : '<div class="empty-state compact"><b>Nenhum registro retornado</b><p>O resolvedor não encontrou respostas para os tipos consultados.</p></div>';
}
function renderCerts() {
  $("#certCount").textContent = `${state.certs.length} ENTRADAS`;
  $("#statCerts").textContent = state.certs.length;
  $("#certResults").innerHTML = state.certs.length ? state.certs.slice(0, 30).map(cert => `
    <div class="cert-item"><div class="cert-top"><b>${escapeHtml(cert.common_name || cert.name_value || "Nome não informado")}</b><span>#${escapeHtml(cert.id)}</span></div>
    <p>Emissor: ${escapeHtml(cert.issuer_name || "Não informado")}<br>Válido: ${escapeHtml(formatDate(cert.not_before))} — ${escapeHtml(formatDate(cert.not_after))}</p></div>
  `).join("") : '<div class="empty-state compact"><b>Nenhuma entrada encontrada</b><p>Não foram retornados certificados ou a fonte está indisponível.</p></div>';
}
function renderStats() {
  $("#statRdap").textContent = state.rdap ? "OK" : "—";
  $("#rdapSub").textContent = state.rdap ? "Resposta recebida" : "Sem resposta";
  renderDns(); renderCerts(); renderRdap(); renderOverview(); updateTargetHeader(); renderInfrastructure();
  renderGraph(); renderDomainIntel(); renderThreatIntel(); renderConfidence();
}
async function analyzeDomain(target) {
  const jobs = await Promise.allSettled([
    Promise.all(DNS_TYPES.map(async type => {
      const data = await fetchJson(API.dns(target.value, type), { headers: { accept: "application/dns-json" } });
      data.typeName = type; return data;
    })),
    fetchJson(API.rdapDomain(target.value)),
    fetchJson(API.certs(target.value), { headers: { accept: "application/json" } }, 15000)
  ]);
  state.dns = jobs[0].status === "fulfilled" ? jobs[0].value : [];
  state.rdap = jobs[1].status === "fulfilled" ? jobs[1].value : null;
  state.certs = jobs[2].status === "fulfilled" && Array.isArray(jobs[2].value) ? jobs[2].value : [];
  state.mailSecurity = null;
  try { state.mailSecurity = { dmarc: await fetchJson(API.dns("_dmarc."+target.value,"TXT"), {headers:{accept:"application/dns-json"}}) }; } catch (_) { state.mailSecurity = {dmarc:null}; }
  const failures = jobs.filter(job => job.status === "rejected").length;
  if (failures === jobs.length) setAlert("As fontes públicas não responderam. Verifique sua conexão e tente novamente.");
  else if (failures) setAlert(`${failures} fonte(s) não responderam. Os demais resultados foram carregados.`);
  renderStats();
}
async function analyzeIp(target) {
  const jobs = await Promise.allSettled([fetchJson(API.ip(target.value)), fetchJson(API.rdapIp(target.value))]);
  state.ipInfo = jobs[0].status === "fulfilled" && jobs[0].value.success !== false ? jobs[0].value : null;
  state.rdap = jobs[1].status === "fulfilled" ? jobs[1].value : null;
  state.dns = []; state.certs = [];
  if (!state.ipInfo && !state.rdap) setAlert("Não foi possível obter dados públicos para este IP.");
  else if (jobs.some(job => job.status === "rejected")) setAlert("Uma das fontes não respondeu. Parte dos dados pode estar indisponível.");
  renderStats();
}
async function runAnalysis(raw) {
  setAlert("");
  let target;
  try { target = normalizeTarget(raw); }
  catch (error) { setAlert(error.message); return; }
  state.target = target; state.dns = []; state.certs = []; state.rdap = null; state.ipInfo = null; state.mailSecurity = null;
  addTimeline("Consulta iniciada",target.value);
  state.runs++; addHistory(target); updateTargetHeader(); renderStats();
  $("#overviewStatus").textContent = "CONSULTANDO";
  $("#searchBtn").disabled = true; $("#searchBtn").querySelector("span").textContent = "CONSULTANDO";
  try {
    if (target.type === "IP") await analyzeIp(target);
    else await analyzeDomain(target);
  } catch (error) {
    setAlert("Falha inesperada durante a consulta. " + error.message);
  } finally {
    $("#searchBtn").disabled = false; $("#searchBtn").querySelector("span").textContent = "ANALISAR";
    $("#overviewStatus").textContent = state.rdap ? "DADOS CARREGADOS" : "RESULTADO PARCIAL";
    showToast("Consulta finalizada.");
  }
}
function renderInvestigations() {
  const el = $("#investigationsContent");
  if (!el) return;
  el.innerHTML = state.history.length ? state.history.map(item =>
    `<div class="history-item"><b>${escapeHtml(item.target)}</b><small>${item.type} · ${item.at.toLocaleString("pt-BR")}</small></div>`
  ).join("") : '<div class="activity-empty"><b>Nenhuma investigação ainda</b><small>Faça uma consulta na barra superior para começar.</small></div>';
}
function renderInfrastructure() {
  const el = $("#infrastructureContent");
  if (!el) return;
  if (!state.target || state.target.type !== "IP") {
    $("#infraStatus").textContent = state.target ? "ALVO NÃO É IP" : "AGUARDANDO ALVO";
    el.innerHTML = '<div class="infra-empty panel-card"><b>Informe um endereço IP</b><p>Este painel mostra geolocalização aproximada e informações de rede para alvos IP.</p></div>';
    return;
  }
  const info=state.ipInfo||{}, loc=info.city||"Cidade não disponível", region=info.region||"Região não disponível", country=info.country||"País não disponível";
  const conn=info.connection||{}, timezone=info.timezone||{}, flag=info.flag?.emoji||"🌐";
  const lat=Number(info.latitude), lon=Number(info.longitude), hasCoords=Number.isFinite(lat)&&Number.isFinite(lon)&&(lat!==0||lon!==0);
  const coords=hasCoords?lat.toFixed(3)+", "+lon.toFixed(3):"Não disponível";
  const asn=conn.asn?"AS"+String(conn.asn).replace(/^AS/i,""):"Não disponível";
  const org=conn.org||conn.isp||"Não disponível", rdapNet=state.rdap?.handle||state.rdap?.name||"Não disponível";
  const mapUrl=hasCoords?"https://www.openstreetmap.org/?mlat="+encodeURIComponent(lat)+"&mlon="+encodeURIComponent(lon)+"#map=9/"+encodeURIComponent(lat)+"/"+encodeURIComponent(lon):"";
  const graph=`<svg viewBox="0 0 700 365" role="img" aria-label="Diagrama ilustrativo de metadados públicos do IP">
    <path class="edge" d="M350 182 L145 75 M350 182 L555 75 M350 182 L145 290 M350 182 L555 290"/>
    <circle cx="350" cy="182" r="47" fill="#123849" stroke="#55e2eb" stroke-width="2" style="filter:drop-shadow(0 0 13px #29d7e788)"/>
    <text x="350" y="178" class="node-label">${escapeHtml(state.target.value)}</text><text x="350" y="195" class="node-sub">IP ANALISADO</text>
    <g><circle class="node-ring" cx="145" cy="75" r="25"/><text x="145" y="79" class="node-label">GEO</text><text x="145" y="116" class="node-sub">${escapeHtml(loc.slice(0,20))}</text></g>
    <g><circle class="node-ring purple" cx="555" cy="75" r="25"/><text x="555" y="79" class="node-label">ASN</text><text x="555" y="116" class="node-sub">${escapeHtml(asn)}</text></g>
    <g><circle class="node-ring" cx="145" cy="290" r="25"/><text x="145" y="294" class="node-label">ISP</text><text x="145" y="331" class="node-sub">${escapeHtml((conn.isp||"Provedor").slice(0,22))}</text></g>
    <g><circle class="node-ring purple" cx="555" cy="290" r="25"/><text x="555" y="294" class="node-label">RDAP</text><text x="555" y="331" class="node-sub">${escapeHtml(rdapNet.slice(0,22))}</text></g>
  </svg>`;
  $("#infraStatus").textContent=state.ipInfo?"METADADOS CARREGADOS":"DADOS PARCIAIS";
  el.innerHTML=`
    <div class="infra-topology-card"><div class="infra-card-head"><div><h3>TOPOLOGIA DE REDE</h3><small>RELAÇÕES A PARTIR DE METADADOS PÚBLICOS</small></div><span class="infra-live">CONSULTA CONCLUÍDA</span></div><div class="infra-topology">${graph}</div></div>
    <div class="infra-side-stack">
      <article class="infra-side-card"><div class="infra-card-head"><div><h3>LOCALIZAÇÃO APROXIMADA</h3><small>GEOIP / BASE PÚBLICA</small></div><span class="infra-live">IP</span></div>
        <div class="infra-location"><div class="infra-country-line"><span class="infra-flag">${escapeHtml(flag)}</span><div><div class="infra-city">${escapeHtml(loc)}</div><div class="infra-region">${escapeHtml(region)} · ${escapeHtml(country)}</div></div></div>
          <div class="infra-location-grid"><div class="infra-mini"><small>COORDENADAS APROX.</small><b>${escapeHtml(coords)}</b></div><div class="infra-mini"><small>FUSO HORÁRIO</small><b>${escapeHtml(timezone.id||timezone.utc||"Não disponível")}</b></div></div>
        </div>${mapUrl?`<a class="infra-map-link" href="${mapUrl}" target="_blank" rel="noopener noreferrer">VER REGIÃO NO OPENSTREETMAP ↗</a>`:""}
      </article>
      <article class="infra-side-card"><div class="infra-card-head"><div><h3>PROVEDOR E REGISTRO</h3><small>ASN / RDAP</small></div></div><div class="infra-details">
        <div class="infra-detail"><small>ORGANIZAÇÃO</small><b>${escapeHtml(org)}</b></div>
        <div class="infra-detail"><small>ASN</small><b>${escapeHtml(asn)}</b></div>
        <div class="infra-detail"><small>PROVEDOR / ISP</small><b>${escapeHtml(conn.isp||"Não disponível")}</b></div>
        <div class="infra-detail"><small>DOMÍNIO DO PROVEDOR</small><b>${escapeHtml(conn.domain||"Não disponível")}</b></div>
        <div class="infra-detail"><small>TIPO DE CONEXÃO</small><b>${escapeHtml(conn.type||"Não disponível")}</b></div>
        <div class="infra-detail"><small>REDE / REGISTRO</small><b>${escapeHtml(rdapNet)}</b></div>
      </div></article>
    </div>
    <div class="infra-kpis">
      <div class="infra-kpi"><small>ENDEREÇO IP</small><b>${escapeHtml(state.target.value)}</b></div>
      <div class="infra-kpi"><small>PAÍS / CÓDIGO</small><b>${escapeHtml(country)} (${escapeHtml(info.country_code||"—")})</b></div>
      <div class="infra-kpi"><small>CONTINENTE</small><b>${escapeHtml(info.continent||"Não disponível")}</b></div>
      <div class="infra-kpi"><small>MOEDA LOCAL</small><b>${escapeHtml(info.currency?.code||"Não disponível")}</b></div>
    </div>`;
}
function switchView(view) {
  const names = { overview:"Dashboard Overview", investigations:"Investigações", framework:"OSINT Framework", infrastructure:"Mapa de infraestrutura", graph:"Investigation Graph", domainintel:"Domain Intelligence", threatintel:"Threat Intelligence", timeline:"Timeline", confidence:"Confidence Score", evidence:"Evidence Center", nametracker:"Name Tracker", emailtracker:"Email Tracker", dns:"Registros DNS", certs:"Certificados", notes:"Relatórios e notas" };
  document.body.dataset.view = view;
  document.querySelectorAll(".nav-item[data-nav]").forEach(button => {
    const active = button.dataset.nav === view;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  document.querySelectorAll(".tab-button[data-tab]").forEach(button => button.classList.toggle("active", button.dataset.tab === view));
  document.querySelectorAll(".tab-panel, .module-panel").forEach(panel => panel.classList.toggle("active", panel.id === `panel-${view}`));
  $("#crumbCurrent").textContent = names[view] || "TRACE";
  if (view === "investigations") renderInvestigations();
  if (view === "infrastructure") renderInfrastructure();
  if (view === "graph") renderGraph();
  if (view === "domainintel") renderDomainIntel();
  if (view === "threatintel") renderThreatIntel();
  if (view === "timeline") renderTimeline();
  if (view === "confidence") renderConfidence();
  if (view === "evidence") renderEvidence();
  if (view === "emailtracker") renderEmailTracker();
  window.scrollTo({top:0,behavior:"smooth"});
}

function addTimeline(action, detail) {
  state.timeline.unshift({at:new Date().toISOString(),action,detail});
  state.timeline=state.timeline.slice(0,100);
  localStorage.setItem("trace_timeline",JSON.stringify(state.timeline));
  renderTimeline();
}
function renderTimeline() {
  const el=$("#timelineContent"); if(!el)return;
  el.innerHTML=state.timeline.length?state.timeline.map(x=>`<div class="timeline-row"><span class="timeline-date">${escapeHtml(new Date(x.at).toLocaleString("pt-BR"))}</span><div><b>${escapeHtml(x.action)}</b><small>${escapeHtml(x.detail)}</small></div></div>`).join(""):'<div class="compact-empty">Nenhuma atividade registrada.</div>';
}
function renderGraph() {
  const el=$("#graphContent"); if(!el)return;
  if(!state.target){el.innerHTML='<div class="empty-state compact"><b>Grafo aguardando consulta</b><p>Analise um domínio ou IP para montar as relações encontradas.</p></div>';return;}
  const nodes=[{label:state.target.value,sub:state.target.type}];
  if(state.ipInfo?.connection?.asn)nodes.push({label:"AS"+state.ipInfo.connection.asn,sub:"ASN",p:true});
  if(state.ipInfo?.connection?.org)nodes.push({label:state.ipInfo.connection.org,sub:"ORGANIZAÇÃO"});
  if(state.ipInfo?.city)nodes.push({label:state.ipInfo.city,sub:"GEOIP APROX."});
  (state.dns.flatMap(x=>(x.Answer||[]).map(a=>({type:x.typeName||x.qtype,data:a.data}))).slice(0,8)).forEach(x=>nodes.push({label:x.data,sub:"DNS "+x.type,p:x.type==="MX"}));
  [...new Set(state.certs.flatMap(c=>String(c.name_value||c.common_name||"").split(/[\n,]+/)).filter(Boolean))].slice(0,6).forEach(x=>nodes.push({label:x,sub:"CERTIFICADO",p:true}));
  const total=nodes.length, cx=500,cy=230,rad=170;
  const circles=nodes.slice(1).map((n,i)=>{const a=(Math.PI*2*i/Math.max(1,total-1))-Math.PI/2,x=cx+Math.cos(a)*rad,y=cy+Math.sin(a)*rad;return { ...n,x,y};});
  const edges=circles.map(n=>`<line class="graph-edge" x1="${cx}" y1="${cy}" x2="${n.x}" y2="${n.y}"/>`).join("");
  const others=circles.map(n=>`<g><circle class="graph-node ${n.p?"secondary":""}" cx="${n.x}" cy="${n.y}" r="23"/><text class="graph-label" x="${n.x}" y="${n.y+4}">${escapeHtml(n.sub.slice(0,9))}</text><text class="graph-sub" x="${n.x}" y="${n.y+39}">${escapeHtml(n.label.slice(0,30))}</text></g>`).join("");
  el.innerHTML=`<div class="graph-content"><svg viewBox="0 0 1000 460" role="img" aria-label="Grafo de relações públicas observadas"><g transform="translate(0 0) scale(1 1)">${edges}${others}<circle class="graph-node" cx="${cx}" cy="${cy}" r="35"/><text class="graph-label" x="${cx}" y="${cy-2}">${escapeHtml(state.target.type)}</text><text class="graph-sub" x="${cx}" y="${cy+13}">ALVO</text></g></svg><p class="module-footnote">Nós periféricos representam dados retornados pelas fontes consultadas. A proximidade no desenho não indica relação técnica além do vínculo com o alvo.</p></div>`;
}
function renderDomainIntel() {
  const sub=$("#subdomainResults"),mail=$("#mailSecurityResults"); if(!sub||!mail)return;
  if(!state.target||state.target.type!=="DOMAIN"){sub.innerHTML='<div class="compact-empty">Consulte um domínio para listar nomes de certificados.</div>';mail.innerHTML='<div class="compact-empty">A verificação de e-mail exige um domínio.</div>';return;}
  const names=[...new Set(state.certs.flatMap(c=>String(c.name_value||c.common_name||"").split(/[\n,]+/)).map(x=>x.trim().toLowerCase()).filter(x=>x&&x.includes(state.target.value)))].sort();
  sub.innerHTML=names.length?names.map(n=>`<div class="intel-row"><b>${escapeHtml(n)}</b><small>Origem: Certificate Transparency (crt.sh)</small></div>`).join(""):'<div class="compact-empty">Nenhum nome correspondente retornado nos certificados consultados. Isso não confirma inexistência de subdomínios.</div>';
  const txt=state.dns.filter(x=>x.typeName==="TXT").flatMap(x=>(x.Answer||[]).map(a=>a.data));
  const spf=txt.find(x=>/^v=spf1/i.test(x));
  const dmarc=state.mailSecurity?.dmarc?.Answer?.flatMap(x=>x.data)||[];
  mail.innerHTML=`<div class="intel-row"><b>SPF</b><small>${spf?"Registro TXT SPF encontrado":"Nenhum SPF identificado na resposta DNS consultada."}</small><span class="intel-status">${spf?"REGISTRO ENCONTRADO":"NÃO IDENTIFICADO"}</span>${spf?`<small>${escapeHtml(spf)}</small>`:""}</div><div class="intel-row"><b>DMARC</b><small>${dmarc.length?"Registro DMARC encontrado":"Nenhum DMARC identificado na consulta."}</small><span class="intel-status">${dmarc.length?"REGISTRO ENCONTRADO":"NÃO IDENTIFICADO"}</span>${dmarc.map(x=>`<small>${escapeHtml(x)}</small>`).join("")}</div>`;
}
function renderThreatIntel() {
 const el=$("#threatIntelContent");if(!el)return;
 if(!state.target){el.innerHTML='<div class="compact-empty">Informe um domínio ou IP para preparar as consultas.</div>';return;}
 const q=encodeURIComponent(state.target.value);
 const links=[["VirusTotal","Reputação e relações observadas pela comunidade.",`https://www.virustotal.com/gui/search/${q}`],["urlscan.io","Pesquisas públicas de páginas e domínios.",`https://urlscan.io/search/#${q}`],["Google Safe Browsing","Verificação de transparência de navegação segura.",`https://transparencyreport.google.com/safe-browsing/search?url=${q}`],["crt.sh","Certificados públicos associados ao domínio.",`https://crt.sh/?q=${q}`],["RDAP","Dados públicos de registro de IP ou domínio.",state.target.type==="IP"?`https://rdap.org/ip/${q}`:`https://rdap.org/domain/${q}`],["Cloudflare DNS","Consulta DNS pública do alvo.",`https://dns.google/resolve?name=${q}`]];
 el.innerHTML=links.map(x=>`<a class="threat-link" href="${x[2]}" target="_blank" rel="noopener noreferrer"><b>${x[0]}</b><span>${x[1]}</span><em>ABRIR CONSULTA ↗</em></a>`).join("");
}
function confidenceData(){
 const parts=[["RDAP",!!state.rdap],["GEOIP",!!state.ipInfo],["DNS",state.dns.some(x=>x.Answer?.length)],["CERTIFICADOS",state.certs.length>0],["SPF / DMARC",state.dns.some(x=>x.typeName==="TXT"&&(x.Answer||[]).some(a=>/^v=spf1/i.test(a.data||""))) || !!state.mailSecurity?.dmarc?.Answer?.length]];
 const available=parts.filter(x=>x[1]).length;return {parts,score:Math.round(available/parts.length*100)};
}
function renderConfidence(){
 const el=$("#confidenceContent");if(!el)return;if(!state.target){el.innerHTML='<div class="compact-empty">Faça uma consulta para calcular a cobertura dos dados.</div>';return;}
 const d=confidenceData();
 el.innerHTML=`<div class="confidence-score">${d.score}<span style="font-size:18px;color:var(--muted)">/100</span></div><p class="module-footnote">Cobertura: ${d.parts.filter(x=>x[1]).length} de ${d.parts.length} grupos de dados disponíveis nesta consulta. Não é uma avaliação de segurança nem uma probabilidade de precisão.</p><div class="confidence-meter"><span style="width:${d.score}%"></span></div><div class="confidence-breakdown">${d.parts.map(x=>`<div class="confidence-part"><small>${x[0]}</small><b>${x[1]?"DISPONÍVEL":"SEM DADOS"}</b></div>`).join("")}</div>`;
}
function evidenceSnapshot(){
 return {captured_at:new Date().toISOString(),target:state.target,rdap:state.rdap,dns:state.dns,certificates:state.certs,ip_metadata:state.ipInfo,mail_security:state.mailSecurity,sources:["rdap.org","cloudflare-dns.com","crt.sh","ipwho.is"]};
}
function renderEvidence(){
 const el=$("#evidenceContent");if(!el)return;
 el.innerHTML=state.evidence.length?state.evidence.map((x,i)=>`<div class="evidence-row"><b>${escapeHtml(x.target?.value||"Alvo")}</b><small>Capturado em ${escapeHtml(new Date(x.captured_at).toLocaleString("pt-BR"))} · ${escapeHtml(x.target?.type||"")}</small><button class="delete-note" data-delete-evidence="${i}">EXCLUIR</button></div>`).join(""):'<div class="compact-empty">Nenhuma evidência salva.</div>';
}
function captureEvidence(){
 if(!state.target){showToast("Faça uma consulta antes de capturar evidências.");return;}
 state.evidence.unshift(evidenceSnapshot());state.evidence=state.evidence.slice(0,50);
 localStorage.setItem("trace_evidence",JSON.stringify(state.evidence));renderEvidence();addTimeline("Evidência capturada",state.target.value);showToast("Snapshot salvo neste navegador.");
}
function exportEvidence(){
 const blob=new Blob([JSON.stringify(state.evidence,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="trace-evidence.json";a.click();URL.revokeObjectURL(url);
}
function switchTab(tab) { switchView(tab); }
function saveNotes() {
  localStorage.setItem("trace_notes", JSON.stringify(state.notes));
  $("#noteCount").textContent = state.notes.length;
}
function renderNotes() {
  $("#noteCount").textContent = state.notes.length;
  $("#notesList").innerHTML = state.notes.length ? state.notes.map(note => `
    <article class="note-card"><h3>${escapeHtml(note.title)}</h3><p>${escapeHtml(note.body)}</p><footer><span>${escapeHtml(note.date)}</span><button class="delete-note" data-delete-note="${escapeHtml(note.id)}">EXCLUIR</button></footer></article>
  `).join("") : '<div class="compact-empty">Nenhuma anotação salva.</div>';
}
function exportReport() {
  if (!state.target) { showToast("Faça uma consulta antes de exportar."); return; }
  const report = {
    generated_at: new Date().toISOString(),
    target: state.target,
    rdap: state.rdap,
    dns: state.dns,
    certificates: state.certs,
    ip_network_metadata: state.ipInfo ? {
      country_code: state.ipInfo.country_code,
      city: state.ipInfo.city, region: state.ipInfo.region, country: state.ipInfo.country,
      latitude: state.ipInfo.latitude, longitude: state.ipInfo.longitude,
      timezone: state.ipInfo.timezone, continent: state.ipInfo.continent,
      connection: state.ipInfo.connection ? {
        asn: state.ipInfo.connection.asn, org: state.ipInfo.connection.org,
        isp: state.ipInfo.connection.isp, type: state.ipInfo.connection.type
      } : null
    } : null,
    notes: state.notes
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob); const a = document.createElement("a");
  a.href = url; a.download = `trace-${state.target.value.replace(/[^a-z0-9.-]/gi, "_")}.json`;
  a.click(); URL.revokeObjectURL(url); showToast("Relatório JSON exportado.");
}


function renderNameTracker(name) {
  const el = $("#nameTrackerResults");
  if (!el) return;
  if (!name) { el.innerHTML = '<div class="compact-empty">Digite um nome para preparar pesquisas em fontes públicas.</div>'; return; }
  const q = encodeURIComponent('"'+name+'"');
  const links = [
    ["Google News", "Menções em notícias públicas.", "https://news.google.com/search?q="+q],
    ["Fontes institucionais", "Páginas públicas de instituições e organizações (.gov.br).", "https://www.google.com/search?q="+encodeURIComponent('"'+name+'" site:gov.br')],
    ["Publicações acadêmicas", "Resultados em publicações e materiais acadêmicos.", "https://scholar.google.com/scholar?q="+q]
  ];
  el.innerHTML = '<div class="tracker-result-summary"><b>Pesquisas preparadas para: '+escapeHtml(name)+'</b><small>Os resultados serão fornecidos pelos sites externos; homônimos são possíveis.</small></div>' +
    links.map(x=>'<a class="tracker-source-link" href="'+x[2]+'" target="_blank" rel="noopener noreferrer"><span><b>'+x[0]+'</b><small>'+x[1]+'</small></span><em>ABRIR ↗</em></a>').join("");
}
async function auditEmail(raw) {
  const email = String(raw || "").trim();
  const match = /^([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)$/.exec(email);
  if (!match || email.length > 254 || match[1].length > 64) throw new Error("Formato de email inválido.");
  const domain = match[2].toLowerCase();
  const provider = domain === "gmail.com" ? "Google Gmail" :
    domain === "outlook.com" || domain === "hotmail.com" || domain === "live.com" ? "Microsoft" :
    domain === "yahoo.com" ? "Yahoo" : "Provedor não identificado";
  const queries = [
    ["MX", domain, "MX"],
    ["TXT", domain, "TXT"],
    ["DMARC", "_dmarc."+domain, "TXT"]
  ];
  const results = await Promise.all(queries.map(async ([label, name, type]) => {
    try {
      const data = await fetchJson(API.dns(name, type), {headers:{accept:"application/dns-json"}});
      return {label, status:data.Status, records:(data.Answer||[]).map(x=>x.data), error:null};
    } catch (error) {
      return {label, status:null, records:[], error:"Fonte DNS indisponível"};
    }
  }));
  const txt = results.find(x=>x.label==="TXT")?.records || [];
  const spf = txt.filter(x=>/^v=spf1/i.test(x));
  const dmarc = results.find(x=>x.label==="DMARC")?.records || [];
  state.emailAudit = {
    checked_at:new Date().toISOString(),
    domain,
    provider,
    syntax_valid:true,
    mx:results.find(x=>x.label==="MX"),
    spf,
    dmarc,
    note:"A análise não confirma a existência da caixa postal nem identifica seu titular."
  };
  renderEmailTracker();
}
function renderEmailTracker() {
  const el=$("#emailTrackerResults"), btn=$("#emailTrackerExport");
  if(!el)return;
  const d=state.emailAudit;
  if(!d){if(btn)btn.disabled=true;return;}
  if(btn)btn.disabled=false;
  const rows=(label,items,unavailable)=>'<div class="tracker-data-row"><div><b>'+label+'</b><small>'+ (items.length?items.map(escapeHtml).join("<br>"):unavailable) +'</small></div><span class="intel-status">'+(items.length?"ENCONTRADO":"NÃO IDENTIFICADO")+'</span></div>';
  const mx=d.mx?.records||[];
  el.innerHTML='<div class="tracker-result-summary"><b>Auditoria técnica concluída</b><small>Domínio: '+escapeHtml(d.domain)+' · '+escapeHtml(new Date(d.checked_at).toLocaleString("pt-BR"))+'</small></div>'+
    '<div class="tracker-metrics">'+
      '<div class="data-tile"><span>FORMATO</span><b>VÁLIDO</b></div>'+
      '<div class="data-tile"><span>PROVEDOR ESTIMADO</span><b>'+escapeHtml(d.provider)+'</b></div>'+
      '<div class="data-tile"><span>DOMÍNIO</span><b>'+escapeHtml(d.domain)+'</b></div>'+
    '</div>'+
    rows("MX — RECEBIMENTO",mx,"Nenhum registro MX retornado ou fonte indisponível.")+
    rows("SPF — AUTENTICAÇÃO",d.spf,"Nenhum registro SPF identificado na resposta.")+
    rows("DMARC — POLÍTICA",d.dmarc,"Nenhum registro DMARC identificado na resposta.")+
    '<p class="tracker-disclaimer">'+escapeHtml(d.note)+'</p>';
}
$("#nameTrackerForm")?.addEventListener("submit",event=>{
  event.preventDefault();
  const name=$("#nameTrackerInput").value.trim();
  if(name.length<2){showToast("Informe um nome válido.");return;}
  renderNameTracker(name);
});
$("#emailTrackerForm")?.addEventListener("submit",async event=>{
  event.preventDefault();
  const button=$("#emailTrackerBtn");button.disabled=true;button.textContent="CONSULTANDO...";
  $("#emailTrackerResults").innerHTML='<div class="compact-empty">Consultando DNS público do domínio...</div>';
  try{await auditEmail($("#emailTrackerInput").value);showToast("Auditoria técnica concluída.");}
  catch(error){$("#emailTrackerResults").innerHTML='<div class="tracker-error">'+escapeHtml(error.message)+'</div>';state.emailAudit=null;renderEmailTracker();}
  finally{button.disabled=false;button.textContent="ANALISAR ↗";}
});
$("#emailTrackerExport")?.addEventListener("click",()=>{
  if(!state.emailAudit)return;
  const blob=new Blob([JSON.stringify(state.emailAudit,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download="trace-email-domain-audit.json";a.click();URL.revokeObjectURL(url);
});

$("#searchForm").addEventListener("submit", event => {
  event.preventDefault(); runAnalysis($("#targetInput").value);
});
document.querySelectorAll("[data-nav]").forEach(button => button.addEventListener("click", () => switchView(button.dataset.nav)));
document.querySelectorAll(".tab-button[data-tab]").forEach(button => button.addEventListener("click", () => switchTab(button.dataset.tab)));
$("#newInvestigationBtn")?.addEventListener("click", () => { switchView("overview"); $("#targetInput").focus(); });

$("#noteForm").addEventListener("submit", event => {
  event.preventDefault();
  state.notes.unshift({ id: crypto.randomUUID(), title: $("#noteTitle").value.trim(), body: $("#noteBody").value.trim(), date: new Date().toLocaleString("pt-BR") });
  saveNotes(); renderNotes(); event.target.reset(); showToast("Anotação salva neste navegador.");
});
$("#notesList").addEventListener("click", event => {
  const button = event.target.closest("[data-delete-note]");
  if (!button) return;
  state.notes = state.notes.filter(note => note.id !== button.dataset.deleteNote);
  saveNotes(); renderNotes(); showToast("Anotação excluída.");
});
$("#exportBtn").addEventListener("click", exportReport);
$("#captureEvidenceBtn")?.addEventListener("click",captureEvidence);
$("#exportEvidenceBtn")?.addEventListener("click",exportEvidence);
$("#printReportBtn")?.addEventListener("click",()=>window.print());
$("#evidenceContent")?.addEventListener("click",event=>{const b=event.target.closest("[data-delete-evidence]");if(!b)return;state.evidence.splice(Number(b.dataset.deleteEvidence),1);localStorage.setItem("trace_evidence",JSON.stringify(state.evidence));renderEvidence();});

renderNotes(); renderHistory(); updateTargetHeader(); renderInvestigations(); renderInfrastructure();
renderTimeline();renderEvidence();renderGraph();renderDomainIntel();renderThreatIntel();renderConfidence();switchView("overview");
