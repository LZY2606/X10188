let SNAP = null;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const short = (o) => o ? o.slice(0, 10) : "—";

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function budgetParams() {
  const p = new URLSearchParams();
  p.set("max_depth", $("b-depth").value || 50);
  p.set("total_bytes", $("b-total").value || 268435456);
  p.set("ratio_millis", $("b-ratio").value || 8000);
  return p.toString();
}

async function refresh() {
  SNAP = await getJSON("/api/snapshot");
  renderSources();
  renderCandidates();
  renderDag();
  renderLayout();
  renderRunSummary();
}

function renderRunSummary() {
  const run = (SNAP.runs || [])[0];
  if (!run) { $("run-summary").textContent = ""; return; }
  let b = {};
  try { b = JSON.parse(run.budget_json); } catch {}
  $("run-summary").textContent =
    `最近运行 #${run.id}（${run.scope}） complete=${run.complete ? "是" : "否（存在可重试中间状态）"} 深度上限=${b.max_depth} 总预算=${b.total_bytes}`;
}

function renderSources() {
  const el = $("sources");
  el.innerHTML = (SNAP.sources || []).map((s) => {
    const impacts = s.deletion_impact.length;
    return `<div class="source-card">
      <div class="name">${esc(s.filename)}</div>
      <div class="meta">#${s.id} · ${s.kind} · ${s.byte_len} B</div>
      <div class="meta">pack_checksum: <small class="oid mono">${short(s.pack_checksum)}</small></div>
      <div class="meta">附着 pack: ${s.attached_pack_id ?? "—"}</div>
      <div><span class="badge ${s.status}">${s.status}</span></div>
      ${s.note ? `<div class="evidence">${esc(s.note)}</div>` : ""}
      <div class="meta">删除影响候选: ${impacts}</div>
      <button onclick="checkDelete(${s.id})">删除前检查依赖</button>
    </div>`;
  }).join("");
}

function renderLayout() {
  const el = $("layout");
  const fanouts = SNAP.fanouts || [];
  if (!fanouts.length) { el.innerHTML = "<small class='oid'>暂无 index fanout / pack 布局数据</small>"; return; }
  el.innerHTML = fanouts.map((f) => {
    const max = Math.max(1, f.cumulative[255] || 1);
    const bars = f.cumulative.map((c) => `<div style="height:${Math.round(10 + (c / max) * 60)}px" title="${c}"></div>`).join("");
    return `<div><small class="oid">源 #${f.source_id} · ${f.kind} · 对象总数 ${f.cumulative[255]}</small><div class="fanout-row">${bars}</div></div>`;
  }).join("");
}

function statusClass(st) { return st; }

function renderCandidates() {
  const body = document.querySelector("#cand-table tbody");
  body.innerHTML = (SNAP.candidates || []).map((c) => {
    const ev = c.parse_error || c.runtime_error
      ? `<span class="evidence">${esc((c.parse_error_code || c.runtime_error_code) + ": " + (c.parse_error || c.runtime_error))}</span>`
      : (c.blocking_chain && c.blocking_chain.length
          ? `<span class="chain">阻塞 ${c.blocking_chain.length} 步</span>` : "");
    return `<tr onclick="showCandidate(${c.id})">
      <td>${c.id}</td>
      <td>#${c.source_id}</td>
      <td>${esc(c.etype)}</td>
      <td class="mono">${c.pack_offset ?? "—"}</td>
      <td>${c.declared_size} / ${c.resolved_size ?? "—"}</td>
      <td class="mono" title="${esc(c.claim_oid ?? "")}">${short(c.claim_oid)}</td>
      <td class="status ${statusClass(c.status)}">${c.status}</td>
      <td>${c.chain_depth ?? "—"}</td>
      <td>${c.claim_alternatives > 1 ? `<b>${c.claim_alternatives}</b> <button onclick="event.stopPropagation();openBranch(${c.id})">分支</button>` : c.claim_alternatives}</td>
      <td>${ev}</td>
    </tr>`;
  }).join("");
}

function renderDag() {
  const svg = $("dag");
  svg.innerHTML = "";
  const cands = SNAP.candidates || [];
  const byId = Object.fromEntries(cands.map((c) => [c.id, c]));
  const W = svg.clientWidth || 900, H = 360;
  const levels = new Map();
  const adj = new Map();
  (SNAP.edges || []).forEach((e) => {
    if (!adj.has(e.from_cand)) adj.set(e.from_cand, []);
    adj.get(e.from_cand).push(e.to_cand);
  });
  // 拓扑分层：base 深度 0，delta 递增
  function depth(id, seen) {
    if (levels.has(id)) return levels.get(id);
    if (seen.has(id)) return 0;
    seen.add(id);
    const outs = (adj.get(id) || []).filter(Boolean);
    const d = outs.length ? 1 + Math.max(...outs.map((t) => depth(t, seen))) : 0;
    levels.set(id, d);
    return d;
  }
  cands.forEach((c) => depth(c.id, new Set()));
  const maxDepth = Math.max(1, ...levels.values());
  const colX = (d) => 40 + (W - 80) * (d / maxDepth);
  const byCol = {};
  cands.forEach((c) => {
    const d = levels.get(c.id) || 0;
    (byCol[d] = byCol[d] || []).push(c.id);
  });
  const pos = {};
  Object.keys(byCol).forEach((d) => {
    const arr = byCol[d];
    arr.forEach((id, i) => {
      pos[id] = { x: colX(Number(d)), y: 30 + i * ((H - 60) / Math.max(1, arr.length)) + 18, d };
    });
  });
  const NS = "http://www.w3.org/2000/svg";
  (SNAP.edges || []).forEach((e) => {
    if (!e.to_cand || !pos[e.from_cand] || !pos[e.to_cand]) {
      // 缺失 base：画一个外部缺失节点
      if (!pos[e.from_cand]) return;
      const px = 60, py = pos[e.from_cand].y;
      const line = document.createElementNS(NS, "line");
      line.setAttribute("x1", pos[e.from_cand].x); line.setAttribute("y1", pos[e.from_cand].y);
      line.setAttribute("x2", px); line.setAttribute("y2", py);
      line.setAttribute("stroke", "#8a7dff"); line.setAttribute("stroke-dasharray", "4 3");
      svg.appendChild(line);
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", 4); t.setAttribute("y", py + 4); t.setAttribute("fill", "#8a7dff");
      t.setAttribute("font-size", "9"); t.textContent = "缺:" + short(e.ref_oid).slice(0, 6);
      svg.appendChild(t);
      return;
    }
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", pos[e.from_cand].x); line.setAttribute("y1", pos[e.from_cand].y);
    line.setAttribute("x2", pos[e.to_cand].x); line.setAttribute("y2", pos[e.to_cand].y);
    line.setAttribute("stroke", e.kind === "ref" ? "#56c2d6" : "#7f8db0");
    svg.appendChild(line);
  });
  cands.forEach((c) => {
    const p = pos[c.id]; if (!p) return;
    const g = document.createElementNS(NS, "g");
    g.style.cursor = "pointer";
    g.addEventListener("click", () => showCandidate(c.id));
    const circ = document.createElementNS(NS, "circle");
    circ.setAttribute("cx", p.x); circ.setAttribute("cy", p.y); circ.setAttribute("r", 7);
    const color = { resolved: "#37b87a", bad: "#ef5f6b", paused: "#e8b341",
      missing_base: "#8a7dff", depth_limit: "#56c2d6" }[c.status] || "#93a0b8";
    circ.setAttribute("fill", color);
    g.appendChild(circ);
    const t = document.createElementNS(NS, "text");
    t.setAttribute("x", p.x + 10); t.setAttribute("y", p.y + 3); t.setAttribute("fill", "#cdd8ee");
    t.setAttribute("font-size", "9"); t.textContent = `#${c.id} ${c.etype} ${short(c.claim_oid)}`;
    g.appendChild(t);
    svg.appendChild(g);
  });
}
