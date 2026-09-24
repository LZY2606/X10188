const $ = (id) => document.getElementById(id);
const state = { objects: [], evidence: [], sources: [], packs: [], selected: null, edges: [] };

async function api(path, opts) {
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

const statusColor = {
  resolved: "#4ade80", error: "#f87171", missing_base: "#fbbf24",
  paused_budget: "#c084fc", cycle: "#fb7185",
};

async function loadAll() {
  const [st, objs, ev, srcs, packs] = await Promise.all([
    api("/api/state"), api("/api/objects"), api("/api/evidence"),
    api("/api/sources"), api("/api/packs"),
  ]);
  $("c-resolved").textContent = st.counts.resolved || 0;
  $("c-missing").textContent = st.counts.missing_base || 0;
  $("c-error").textContent = st.counts.error || 0;
  $("c-paused").textContent = st.counts.paused_budget || 0;
  $("c-cycle").textContent = st.counts.cycle || 0;
  const used = st.budget.total_expanded_used, max = st.budget.max_total_expanded;
  $("budget-chip").innerHTML = `expanded <b>${used}</b> / ${max} bytes`;
  $("b-depth").value = st.budget.max_depth;
  $("b-total").value = st.budget.max_total_expanded;
  $("b-ratio").value = st.budget.max_single_ratio;
  const pct = Math.min(100, (used / Math.max(1, max)) * 100);
  $("b-bar").style.width = pct + "%";
  $("b-label").textContent = `${used} / ${max} bytes used (${pct.toFixed(1)}%)`;
  state.objects = objs.objects;
  state.evidence = ev.evidence;
  state.sources = srcs.sources;
  state.packs = packs.packs;
  renderObjects(); renderEvidence(); renderSources(); renderPackSelect(); renderDag();
}

function renderObjects() {
  const f = $("filter").value.trim().toLowerCase();
  const tb = document.querySelector("#obj-table tbody");
  tb.innerHTML = "";
  for (const o of state.objects) {
    const hay = (o.oid + o.status + o.type).toLowerCase();
    if (f && !hay.includes(f)) continue;
    const tr = document.createElement("tr");
    tr.className = "obj";
    tr.innerHTML = `<td>${short(o.oid)}</td>
      <td class="status s-${o.status}">${o.status}</td>
      <td>${o.type || ""}</td><td>${o.size || 0}</td><td>${o.depth || 0}</td>`;
    tr.onclick = () => showObject(o.oid);
    tb.appendChild(tr);
  }
}
function short(oid){ return oid.startsWith("unresolved") ? oid.replace("unresolved_","?") : oid.slice(0,12)+"…"; }

function renderEvidence() {
  const box = $("evidence");
  box.innerHTML = state.evidence.slice(0, 80).map((e) => `
    <div style="margin-bottom:6px">
      <span class="ev-${e.severity}">●</span>
      <span class="badge">${e.code}</span>
      <div class="muted">${escapeHtml(e.message)}</div>
      ${e.detail ? `<div class="muted" style="font-size:11px">${escapeHtml(e.detail.slice(0,160))}</div>` : ""}
    </div>`).join("");
}

function renderSources() {
  const box = $("sources");
  box.innerHTML = state.sources.map((s) => `
    <div style="margin-bottom:6px;border:1px solid var(--line);border-radius:6px;padding:5px 7px">
      <div><span class="tag">${s.kind}</span> <b>${escapeHtml(s.name)}</b></div>
      <div class="muted">${s.bytes} bytes · ${s.status}${s.error ? " · "+escapeHtml(s.error) : ""}</div>
      <div class="row" style="margin:3px 0 0">
        <button data-dep="${s.id}">依赖</button>
        <button data-del="${s.id}">删除</button>
      </div>
    </div>`).join("");
  box.querySelectorAll("[data-dep]").forEach((b) => b.onclick = async () => {
    const j = await api(`/api/sources/${b.dataset.dep}/dependents`);
    alert(j.dependents.length ? ("仍被依赖:\n" + j.dependents.join("\n")) : "没有对象依赖该源，可安全删除。");
  });
  box.querySelectorAll("[data-del]").forEach((b) => b.onclick = async () => {
    try { await api(`/api/sources/${b.dataset.del}`, { method: "POST" }); await loadAll(); }
    catch (e) { alert("无法删除：\n" + e.message); }
  });
}

function renderPackSelect() {
  const sel = $("pack-select");
  const cur = sel.value;
  sel.innerHTML = state.packs.map((p) =>
    `<option value="${p.id}">#${p.id} ${escapeHtml(p.name)} (${p.objects} objs)</option>`).join("");
  if (cur) sel.value = cur;
  if (state.packs.length) loadLayout(sel.value);
  else { $("layout").innerHTML = ""; $("fanout").textContent = ""; }
}

async function loadLayout(packId) {
  const j = await api(`/api/packs/${packId}/layout`);
  if (!j.found) return;
  const bodyLen = j.pack.body_len;
  const typeColor = { blob:"#5ec8f2", tree:"#4ade80", commit:"#fbbf24", tag:"#f472b6",
                      ofs_delta:"#c084fc", ref_delta:"#fb923c" };
  $("layout").innerHTML = j.entries.map((e) => {
    const w = Math.max(2, (e.offset / Math.max(1, bodyLen)) * 100);
    const color = typeColor[e.type] || "#94a3b8";
    return `<div class="layout-entry" data-off="${e.offset}">
      <div class="swatch" style="background:${color}"></div>
      <div style="flex:1"><b>@${e.offset}</b> <span class="tag">${e.type}</span>
        declared ${e.declared_size}B
        ${e.base_offset >= 0 ? `· base@${e.base_offset}` : ""}
        ${e.base_oid ? `· ref ${e.base_oid.slice(0,10)}…` : ""}
      </div>
      <div class="muted">zlib [${e.z_start}, +${e.z_consumed < 0 ? "?" : e.z_consumed})</div>
      ${e.error ? `<span class="ev-error">⚠ ${escapeHtml(e.error.slice(0,40))}</span>` : ""}
    </div>`;
  }).join("");
  $("layout").querySelectorAll(".layout-entry").forEach((el) =>
    el.onclick = () => showObjectByOffset(packId, Number(el.dataset.off)));
  if (j.fanout) {
    const total = j.fanout[255];
    const nonEmpty = j.fanout.map((v,i)=>[i,v]).filter(([i,v])=>v>(i?j.fanout[i-1]:0)).length;
    $("fanout").innerHTML = `fanout 256 项，覆盖 <b>${total}</b> 个对象，${nonEmpty} 个首字节桶非空 · pack checksum ${j.pack.checksum_ok ? "✅" : "❌"}`;
  }
}

// ---- DAG rendering (simple layered layout from /api/objects + steps) ----
async function renderDag() {
  const svg = $("dag");
  svg.innerHTML = "";
  // Fetch steps lazily only for resolved delta objects.
  const nodes = state.objects.filter((o) => o.oid && !o.oid.startsWith("unresolved"));
  const unresolved = state.objects.filter((o) => o.oid.startsWith("unresolved"));
  const W = svg.clientWidth || 800;
  const level = {};
  const infos = {};
  for (const o of nodes) infos[o.oid] = o;

  // gather edges from steps endpoints (batch cheaply: only delta objs)
  const edgeList = [];
  for (const o of nodes) {
    if (o.depth > 0) {
      try {
        const d = await api(`/api/objects/${encodeURIComponent(o.oid)}?branch=default`);
        if (d.steps) {
          for (const s of d.steps) {
            if (s.base_oid && infos[s.base_oid]) edgeList.push([s.base_oid, o.oid, s.base_kind]);
          }
        }
      } catch (e) {}
    }
  }
  // longest-chain levels
  const adj = {};
  for (const [a, b] of edgeList) { (adj[b] ||= []).push(a); }
  const memo = {};
  const lvl = (oid) => {
    if (memo[oid] !== undefined) return memo[oid];
    memo[oid] = 0;
    let m = 0;
    for (const p of (adj[oid] || [])) m = Math.max(m, lvl(p) + 1);
    memo[oid] = m; return m;
  };
  const byLevel = {};
  for (const o of nodes) { (byLevel[lvl(o.oid)] ||= []).push(o.oid); }
  const margin = 40, colW = 150, rowH = 70;
  const cols = Math.max(1, Object.keys(byLevel).length);
  svg.setAttribute("width", Math.max(W, cols * colW + 80));
  svg.setAttribute("height", Math.max(420, Math.max(0, ...Object.values(byLevel).map(v=>v.length)) * rowH + 80));
  const pos = {};
  Object.keys(byLevel).sort((a,b)=>a-b).forEach((lv) => {
    byLevel[lv].forEach((oid, i) => { pos[oid] = { x: margin + Number(lv)*colW, y: margin + i*rowH }; });
  });
  const ns = "http://www.w3.org/2000/svg";
  for (const [a, b, kind] of edgeList) {
    const p1 = pos[a], p2 = pos[b]; if (!p1 || !p2) continue;
    const line = document.createElementNS(ns, "path");
    const x1 = p1.x + 90, y1 = p1.y + 18, x2 = p2.x, y2 = p2.y + 18;
    line.setAttribute("d", `M${x1},${y1} C${(x1+x2)/2},${y1} ${(x1+x2)/2},${y2} ${x2},${y2}`);
    line.setAttribute("stroke", kind === "ofs" ? "#c084fc" : "#fb923c");
    line.setAttribute("fill", "none"); line.setAttribute("stroke-width", "1.5");
    svg.appendChild(line);
  }
  for (const oid of Object.keys(pos)) {
    const o = infos[oid], p = pos[oid];
    const g = document.createElementNS(ns, "g");
    g.setAttribute("transform", `translate(${p.x},${p.y})`);
    g.style.cursor = "pointer";
    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("width", 96); rect.setAttribute("height", 38); rect.setAttribute("rx", 6);
    rect.setAttribute("fill", "#1e2740"); rect.setAttribute("stroke", statusColor[o.status] || "#94a3b8");
    g.appendChild(rect);
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", 6); t.setAttribute("y", 15);
    t.textContent = oid.slice(0, 10) + "…"; g.appendChild(t);
    const t2 = document.createElementNS(ns, "text");
    t2.setAttribute("x", 6); t2.setAttribute("y", 30);
    t2.textContent = `${o.type || "?"} ${o.size}B d${o.depth||0}`; g.appendChild(t2);
    g.onclick = () => showObject(oid);
    svg.appendChild(g);
  }
  // unresolved cluster
  unresolved.forEach((u, i) => {
    const g = document.createElementNS(ns, "g");
    g.setAttribute("transform", `translate(${margin + Math.max(0,(cols-1))*colW},${margin + i*rowH + 240})`);
    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("width", 120); rect.setAttribute("height", 40); rect.setAttribute("rx", 6);
    rect.setAttribute("fill", "#2a1a1a"); rect.setAttribute("stroke", statusColor[u.status]);
    g.appendChild(rect);
    const t = document.createElementNS(ns, "text"); t.setAttribute("x",6); t.setAttribute("y",15);
    t.textContent = u.status; g.appendChild(t);
    const t2 = document.createElementNS(ns, "text"); t2.setAttribute("x",6); t2.setAttribute("y",30);
    t2.textContent = (u.reason || "").slice(0, 20); g.appendChild(t2);
    g.style.cursor = "pointer"; g.onclick = () => showObject(u.oid);
    svg.appendChild(g);
  });
}

async function showObjectByOffset(packId, off) {
  // find resolution row whose candidate points at this entry is not directly
  // available via list; expose detail by a helper query on objects filtered.
  const target = state.objects.find((o) => o.oid.includes(`pack${packId}@${off}`));
  if (target) showObject(target.oid);
  else alert("该条目没有对应的 resolution 行（可能解析在中途中止）。");
}

async function showObject(oid) {
  const box = $("detail");
  box.innerHTML = "加载中…";
  const d = await api(`/api/objects/${encodeURIComponent(oid)}?branch=default`);
  if (!d.found) { box.innerHTML = `<div class="muted">未找到 ${escapeHtml(oid)}</div>`; return; }
  const r = d.resolution;
  box.innerHTML = `
    <div><span class="status s-${r.status}">${r.status}</span>
      <span class="tag">${r.type || "?"}</span></div>
    <div class="muted" style="word-break:break-all;margin:4px 0">${r.oid}</div>
    <div class="muted">size ${r.size} · depth ${r.depth} · expanded ${r.expanded}</div>
    ${r.reason ? `<div class="ev-error" style="margin:6px 0">${escapeHtml(r.reason)}</div>`:""}
    ${r.blocking_chain && r.blocking_chain.length ? `
      <h2>阻塞链</h2><div id="chain"></div>` : ""}
    ${d.steps && d.steps.length ? `<h2 style="margin-top:10px">Delta 步骤</h2><div id="steps"></div>` : ""}
    ${d.candidates && d.candidates.length ? `<h2 style="margin-top:10px">候选来源 (固定冲突来源)</h2><div id="cands"></div>` : ""}
    ${d.preview ? `<h2 style="margin-top:10px">内容预览</h2>
      <pre>${escapeHtml(d.preview.slice(0, 4000))}</pre>` : ""}
  `;
  if (r.blocking_chain && r.blocking_chain.length) {
    $("chain").innerHTML = r.blocking_chain.map((h, i) =>
      `<div class="step"><b>#${i}</b> ${escapeHtml(h.from)}
        <span class="badge">${h.via}</span> → ${escapeHtml(h.target)}
        ${h.detail ? `<div class="muted">${escapeHtml(h.detail)}</div>`:""}</div>`).join("");
  }
  if (d.steps) {
    $("steps").innerHTML = d.steps.map((s) => `
      <div class="step">step ${s.step} · base <span class="badge">${s.base_kind}</span>
        ${escapeHtml((s.base_location||s.base_oid||"").slice(0,48))}
        <div class="muted">cmd[${s.cmd_start}..${s.cmd_end}] ×${s.cmd_count} ·
          in ${s.in_len}B → out ${s.out_len}B ·
          校验 ${s.check_ok ? "✅" : "❌ "+escapeHtml(s.check_detail)}</div>
      </div>`).join("");
  }
  if (d.candidates) {
    $("cands").innerHTML = d.candidates.map((c) => `
      <div class="candidate">
        <div><span class="tag">${c.origin}</span> chain=${c.chain_len}
          <div class="muted" style="font-size:11px;word-break:break-all">${escapeHtml(c.sort_key)}</div>
        </div>
        <button data-pin="${c.id}" ${c.pinned?"disabled":""}>${c.pinned?"已固定":"固定"}</button>
      </div>`).join("");
    $("cands").querySelectorAll("[data-pin]").forEach((b) => b.onclick = async () => {
      await api(`/api/branches/default/pins`, { method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ oid: r.oid, candidate_id: Number(b.dataset.pin) }) });
      await loadAll(); showObject(r.oid);
    });
  }
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

$("upload").onclick = async () => {
  const files = $("files").files;
  if (!files.length) return;
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  $("upload-msg").textContent = "导入中…";
  try {
    const j = await api("/api/upload", { method: "POST", body: fd });
    $("upload-msg").innerHTML = j.imported.map((i) =>
      `✔ ${i.kind} #${i.source_id}: resolved=${i.report.resolved} missing=${i.report.missing_base} paused=${i.report.paused_budget} err=${i.report.error}`).join("<br>");
    await loadAll();
  } catch (e) { $("upload-msg").textContent = "✘ " + e.message; }
};
$("refresh").onclick = loadAll;
$("filter").oninput = renderObjects;
$("pack-select").onchange = (e) => loadLayout(e.target.value);
$("b-save").onclick = async () => {
  await api("/api/budget", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ max_depth: Number($("b-depth").value),
      max_total_expanded: Number($("b-total").value),
      max_single_ratio: Number($("b-ratio").value) }) });
  loadAll();
};
$("b-reset").onclick = async () => { await api("/api/budget/reset", {method:"POST"}); loadAll(); };
$("retry").onclick = async () => { const r = await api("/api/retry",{method:"POST"});
  alert(`retry: resolved=${r.resolved} paused=${r.paused_budget} missing=${r.missing_base} error=${r.error}`);
  loadAll(); };
document.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => {
  document.querySelectorAll(".tabs button").forEach(x=>x.classList.remove("active"));
  b.classList.add("active");
  ["dag","layout","objects"].forEach((t) => $("tab-"+t).style.display = t===b.dataset.tab?"":"none");
  if (b.dataset.tab === "dag") renderDag();
});
loadAll();
