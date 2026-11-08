/* TRACE OSINT Workspace — consultas passivas a fontes públicas. */
"use strict";

const $ = (selector) => document.querySelector(selector);
const state = {
  target: null, dns: [], certs: [], rdap: null, ipInfo: null,
  runs: 0, history: [], notes: JSON.parse(localStorage.getItem("trace_notes") || "[]")
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
  state.target = target; state.dns = []; state.certs = []; state.rdap = null; state.ipInfo = null;
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
  const names = { overview:"Dashboard Overview", investigations:"Investigações", framework:"OSINT Framework", infrastructure:"Mapa de infraestrutura", dns:"Registros DNS", certs:"Certificados", notes:"Relatórios e notas" };
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
  window.scrollTo({top:0,behavior:"smooth"});
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
renderNotes(); renderHistory(); updateTargetHeader(); renderInvestigations(); renderInfrastructure(); switchView("overview");
