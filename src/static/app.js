const $ = (s) => document.querySelector(s);
const state = { branch: 1, nodes: [], packs: [], selected: null };

function esc(s){ return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function short(h){ return h ? h.slice(0,10) : '—'; }

function banner(msg, kind=''){
  const b = $('#banner');
  b.textContent = msg; b.className = 'banner ' + kind;
  if(kind==='ok') setTimeout(()=>b.classList.add('hidden'), 4000);
}

async function api(path, opts){
  const r = await fetch(path, opts);
  const txt = await r.text();
  let data = {}; try{ data = txt ? JSON.parse(txt) : {}; }catch{ data = {raw: txt}; }
  if(!r.ok) throw Object.assign(new Error(data.error || r.statusText), {data, status:r.status});
  return data;
}

async function refreshAll(){
  await Promise.all([loadBranches(), loadBudgets(), loadPacks(), loadNodes()]);
}

async function loadBudgets(){
  const b = await api('/api/budgets');
  $('#b-total').value = b.total_bytes;
  $('#b-ratio').value = b.single_ratio;
  $('#b-depth').value = b.max_depth;
}

async function loadBranches(){
  const d = await api('/api/branches');
  const sel = $('#branch-select');
  sel.innerHTML = '';
  d.branches.forEach(b => {
    const o = document.createElement('option');
    o.value = b.id; o.textContent = `${b.name} (${b.resolved}✓/${b.unresolved}✗)`;
    if(b.id === state.branch) o.selected = true;
    sel.appendChild(o);
  });
}

async function loadPacks(){
  const d = await api('/api/packs');
  state.packs = d.packs;
  const host = $('#packs'); host.innerHTML='';
  if(!d.packs.length){ host.innerHTML='<div class="empty">尚未导入 pack</div>'; return; }
  d.packs.forEach(p => {
    const div = document.createElement('div'); div.className='pack';
    const errs = (p.scan_errors||[]).map(e=>`<div class="ev">${esc(e)}</div>`).join('');
    const segs = p.entries.map(e=>{
      const w = Math.max(2, (e.declared_size? 1:0) + Math.log10((e.compressed_len||1)+1)*6);
      const bad = (e.parse_errors&&e.parse_errors.length) || e.crc_ok===false ? 'bad':'';
      return `<div class="seg ${esc(e.kind)} ${bad}" style="flex:0 0 ${w*6}px" title="offset ${e.offset} ${esc(e.kind)} crc ${esc(e.record_crc||'')}" data-node="${e.node_id}"></div>`;
    }).join('');
    div.innerHTML = `
      <h3>#${p.source_id} ${esc(p.filename)} ${p.trailer_ok?'':'<span class="pill parse-error">trailer 错</span>'}</h3>
      <div class="meta">v${p.version} · ${p.object_count} 对象 · ${p.raw_len} 字节 · trailer ${short(p.trailer_sha)}</div>
      <div class="layout">${segs}</div>
      <div class="legend">
        <span><i style="background:#244f6e"></i>full</span>
        <span><i style="background:#5b3f8c"></i>ofs-delta</span>
        <span><i style="background:#7a5a1f"></i>ref-delta</span>
        <span><i style="background:#8f2d2d"></i>损坏 / CRC 错</span>
      </div>${errs}`;
    div.querySelectorAll('.seg').forEach(s => s.onclick = ()=>selectNode(+s.dataset.node));
    host.appendChild(div);
  });
}

async function loadNodes(){
  const d = await api(`/api/nodes?branch_id=${state.branch}`);
  state.nodes = d.nodes;
  // table
  const tb = $('#nodes-table tbody'); tb.innerHTML='';
  d.nodes.forEach(n => {
    const tr = document.createElement('tr'); tr.className='row';
    const ev = (n.parse_errors||[]).length || n.error ? '⚠' : '';
    tr.innerHTML = `<td>#${n.id}</td><td>${n.source_id}</td><td>${n.offset}</td>
      <td>${esc(n.kind)}${n.resolved_type?`/${n.resolved_type}`:''}</td>
      <td><span class="pill ${esc(n.status||'new')}">${esc(n.status||'待解析')}</span></td>
      <td class="oid">${short(n.resolved_oid)}</td><td>${n.chain_depth??''}</td>
      <td>${ev}</td>`;
    tr.onclick = ()=>selectNode(n.id);
    tb.appendChild(tr);
  });
  renderDag(d.nodes);
}

function renderDag(nodes){
  // layers by chain depth (resolved chain_depth); group by base targets
  const host = $('#dag'); host.innerHTML='';
  if(!nodes.length){ host.innerHTML='<div class="empty">无节点</div>'; return; }
  // Build edges from kind/ofs/ref; layered layout by chain_depth if present.
  const byId = Object.fromEntries(nodes.map(n=>[n.id,n]));
  // simple edges: deltas at same source sorted by offset chain via base_ofs
  const layers = {};
  nodes.forEach(n=>{
    const d = n.chain_depth ?? (n.kind==='full'||n.kind==='loose'?1:2);
    (layers[d] ||= []).push(n);
  });
  Object.keys(layers).sort((a,b)=>+a-+b).forEach(depth=>{
    const row = document.createElement('div'); row.className='depthrow';
    row.innerHTML = `<div class="depth-label">depth ${depth}</div>`;
    layers[depth].forEach((n,i)=>{
      if(i) row.insertAdjacentHTML('beforeend','<span class="edge">→</span>');
      const cls = n.status==='resolved'?'ok':(n.status==='missing-base'||n.status==='budget-paused'?'warn':'bad');
      const el = document.createElement('span');
      el.className = `node ${cls}`;
      el.innerHTML = `#${n.id} <span class="small">${esc(n.kind)}@${n.offset}</span>`;
      el.onclick = ()=>selectNode(n.id);
      row.appendChild(el);
    });
    host.appendChild(row);
  });
  const _ = byId;
}

async function selectNode(id){
  state.selected = id;
  let d;
  try { d = await api(`/api/nodes/${id}/${state.branch}`); }
  catch(e){ banner('加载详情失败: '+e.message,'bad'); return; }
  $('#detail-title').textContent = `节点 #${d.id}`;
  const host = $('#detail');
  const errs = (d.parse_errors||[]).map(e=>`<div class="ev">${esc(e)}</div>`).join('');
  const chain = d.blocked_chain;
  let chainHtml = '';
  if(chain && chain.length){
    chainHtml = `<h4>阻塞链</h4>` + chain.map(l=>
      `<div class="ev warn">节点 src#${l.node.source_id}@${l.node.offset} (${esc(l.kind)}) — ${esc(l.reason)}
       ${l.needs?`<div class="small">需要 ${esc(l.needs.kind)} ${esc(l.needs.oid_hex||l.needs.offset||'')}</div>`:''}</div>`
    ).join('');
  }
  const steps = (d.delta_steps||[]).map(s=>`
    <div class="step ${s.check_ok?'':'bad'}">
      <b>#${s.step_index} ${esc(s.kind)}</b>
      指令字节 [${s.delta_start}..${s.delta_end}) · size=${s.size}
      ${s.copy_offset!=null?` · copy@${s.copy_offset}`:''}
      → 输入位置 ${s.input_pos}, 输出累计 ${s.output_len_after}
      ${s.check_ok?'<span class="pill resolved">校验通过</span>':`<span class="pill bad-object">${esc(s.check_error)}</span>`}
    </div>`).join('');
  const cands = (d.candidates||[]).map(c=>`
    <div class="cand">
      <span class="oid">${esc(c.oid)}</span>
      <span>${esc(c.origin)} · ${esc(c.source_label)} · conf ${c.confidence}
        ${c.hash_match?'<span class="pill resolved">hash✓</span>':'<span class="pill parse-error">hash✗</span>'}</span>
      ${state.branch!==1?`<button data-pin="${c.oid}">固定为此来源</button>`:''}
    </div>`).join('');
  const tname = {1:'commit',2:'tree',3:'blob',4:'tag'}[d.resolved_type] || '';
  host.innerHTML = `
    <div class="kv">
      <div>源 / 偏移</div><div>src#${d.source_id} @ ${d.offset} (${esc(d.kind)})</div>
      <div>声明大小</div><div>${d.declared_size}（实际解压 ${d.inflated_size}）</div>
      <div>头 / 压缩长度</div><div>${d.header_len} / ${d.compressed_len} 字节（zlib 边界）</div>
      <div>CRC</div><div>${esc(d.record_crc||'—')} / idx期望 ${esc(d.expected_crc||'—')}
        ${d.crc_ok===true?'<span class="pill resolved">一致</span>':d.crc_ok===false?'<span class="pill bad-object">不一致</span>':''}</div>
      <div>base</div><div>${d.base_ofs!=null?('ofs → '+d.base_ofs):esc(d.base_ref_oid||'—')}</div>
      <div>状态</div><div><span class="pill ${esc(d.status||'')}">${esc(d.status||'—')}</span> 深度 ${d.chain_depth??'—'}</div>
      <div>还原 OID</div><div class="oid">${esc(d.resolved_oid||'—')} ${tname?`(${tname}) ${d.content_len} 字节`:''}</div>
    </div>
    ${d.error?`<div class="ev">${esc(d.error)}</div>`:''}
    ${errs}${chainHtml}
    ${cands?`<h4>OID 候选来源（排序与导入顺序无关）</h4>${cands}`:''}
    ${steps?`<h4>Delta 指令（base / 指令范围 / 输入输出 / 校验）</h4>${steps}`:''}
    ${d.content_preview?`
      <h4>还原内容预览</h4>
      ${d.content_preview.is_text?`<pre>${esc(d.content_preview.ascii)}</pre>`:`<pre>${esc(d.content_preview.hex.slice(0,512))}</pre>`}
      <div class="small">${d.content_preview.shown}/${d.content_preview.total} 字节${d.content_preview.truncated?'（已截断）':''}</div>
    `:''}
    ${d.payload_preview?`
      <h4>原始（delta）负载预览</h4>
      ${d.payload_preview.is_text?`<pre>${esc(d.payload_preview.ascii)}</pre>`:`<pre>${esc(d.payload_preview.hex.slice(0,256))}</pre>`}`:''}
  `;
  host.querySelectorAll('[data-pin]').forEach(btn=>{
    btn.onclick = async ()=>{
      try{
        await api(`/api/branches/${state.branch}/pin`, {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({node_id:d.id, oid:btn.dataset.pin})
        });
        banner('已固定候选来源并重算依赖子图','ok');
        await refreshAll(); selectNode(d.id);
      }catch(e){ banner('固定失败: '+e.message,'bad'); }
    };
  });
}

$('#upload-form').onsubmit = async (e)=>{
  e.preventDefault();
  const files = $('#files').files;
  if(!files.length){ banner('请先选择文件',''); return; }
  const fd = new FormData();
  for(const f of files) fd.append('files', f);
  try{
    const r = await api('/api/sources',{method:'POST',body:fd});
    const s = r.summary;
    banner(`导入完成：解析 ${s.resolved}，缺 base ${s.missing_base}，环 ${s.cycle}，坏 ${s.bad_object}${s.paused?'，预算暂停（可恢复）':''}`,
      s.paused || s.missing_base ? '' : 'ok');
    await refreshAll();
  }catch(err){ banner('导入失败: '+err.message,'bad'); }
};

$('#branch-select').onchange = async (e)=>{
  state.branch = +e.target.value;
  await loadNodes();
  if(state.selected) selectNode(state.selected);
};

$('#new-branch-btn').onclick = async ()=>{
  const name = $('#new-branch').value.trim();
  if(!name) return;
  try{
    const r = await api('/api/branches',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name})});
    state.branch = r.id; $('#new-branch').value='';
    await refreshAll(); banner(`已创建分析分支 #${r.id}`,'ok');
  }catch(e){ banner('建分支失败: '+e.message,'bad'); }
};

$('#save-budget').onclick = async ()=>{
  await api('/api/budgets',{method:'POST',headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      total_bytes:+$('#b-total').value, single_ratio:+$('#b-ratio').value, max_depth:+$('#b-depth').value
    })});
  banner('预算已保存（下次解析生效）','ok');
};

$('#resume-btn').onclick = async ()=>{
  try{
    const s = await api('/api/resume',{method:'POST',headers:{'Content-Type':'application/json'},
      body: JSON.stringify({branch_id:state.branch, total_bytes:+$('#b-total').value})});
    banner(s.paused?'仍受预算限制，已保存可恢复中间状态':'恢复解析完成','ok');
    await refreshAll();
  }catch(e){ banner('恢复失败: '+e.message,'bad'); }
};

refreshAll();
