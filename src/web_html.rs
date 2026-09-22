pub const HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>包链显微镜</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#2b3340;--fg:#e6edf3;--dim:#8b97a7;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--pause:#bc8cff;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
header h1{font-size:20px;margin:0;letter-spacing:2px}
header .sub{color:var(--dim);font-size:12px}
.wrap{display:grid;grid-template-columns:330px 1fr 380px;gap:12px;padding:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
.panel h2{font-size:13px;margin:0 0 10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px}
button{background:#21262d;color:var(--fg);border:1px solid var(--line);border-radius:5px;padding:5px 10px;cursor:pointer;font-size:12px}
button:hover{border-color:var(--accent)}
button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
input,select{background:#0d1117;border:1px solid var(--line);color:var(--fg);border-radius:5px;padding:5px 7px;font-size:12px}
.row{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.muted{color:var(--dim);font-size:12px}
.pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-family:var(--mono)}
.pill.complete{background:rgba(63,185,80,.18);color:var(--ok)}
.pill.blocked{background:rgba(210,153,34,.18);color:var(--warn)}
.pill.paused{background:rgba(188,140,255,.18);color:var(--pause)}
.pill.error{background:rgba(248,81,73,.18);color:var(--err)}
.pill.fresh{background:#2b3340;color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;position:sticky;top:0;background:var(--panel)}
td.mono,.mono{font-family:var(--mono)}
.src{cursor:pointer;padding:6px 8px;border:1px solid var(--line);border-radius:6px;margin-bottom:6px}
.src:hover{border-color:var(--accent)}
.obj{cursor:pointer;padding:3px 6px;border-radius:4px}
.obj:hover{background:var(--panel2)}
.obj.sel{background:#12263f;outline:1px solid var(--accent)}
.layout{display:flex;align-items:stretch;gap:2px;overflow-x:auto;padding:8px 0}
.lblock{min-width:26px;border-radius:3px;position:relative;cursor:pointer}
.lblock:hover{outline:2px solid var(--accent)}
.legend{display:flex;gap:10px;flex-wrap:wrap;font-size:11px;color:var(--dim);margin-top:6px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:3px}
pre{background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:8px;overflow:auto;max-height:240px;font-family:var(--mono);font-size:11.5px;white-space:pre-wrap;word-break:break-all}
.ev{border-left:3px solid var(--err);padding:4px 8px;margin:5px 0;background:rgba(248,81,73,.07);border-radius:0 5px 5px 0;font-size:12px}
.ev.warn{border-color:var(--warn);background:rgba(210,153,34,.07)}
.ev .code{font-family:var(--mono);color:var(--err);font-weight:700}
.ev.warn .code{color:var(--warn)}
.step{font-family:var(--mono);font-size:11.5px;padding:3px 6px;border-bottom:1px solid var(--line)}
.step.bad{color:var(--err)}
.step .k{display:inline-block;min-width:56px;color:var(--accent)}
svg.dag{width:100%;height:320px;background:#0d1117;border:1px solid var(--line);border-radius:6px}
.node rect{stroke-width:1.2;cursor:pointer}
.node text{fill:var(--fg);font-size:10px;font-family:var(--mono)}
.edge{stroke:#58a6ff;stroke-width:1.4;fill:none;marker-end:url(#arrow)}
.edge.delta{stroke:#bc8cff}
#toast{position:fixed;right:16px;bottom:16px;background:var(--panel2);border:1px solid var(--accent);padding:10px 14px;border-radius:8px;display:none;max-width:420px;font-size:12px}
details summary{cursor:pointer;color:var(--dim);font-size:12px;margin:6px 0}
.bgrid{display:grid;grid-template-columns:1fr 130px;gap:6px;align-items:center;font-size:12px}
a{color:var(--accent)}
.small{font-size:11px;color:var(--dim)}
</style>
</head>
<body>
<header>
  <h1>包链显微镜</h1>
  <span class="sub">Git pack / index / loose object 取证 · delta 链逐指令还原 · 核心解析不调用系统 git</span>
  <span style="flex:1"></span>
  <span class="small" id="budgetline"></span>
</header>
<div class="wrap">
  <div class="panel" id="left">
    <h2>导入 / 源文件</h2>
    <div class="row">
      <input type="file" id="file" multiple style="font-size:11px;max-width:200px"/>
      <button class="primary" onclick="upload()">导入</button>
    </div>
    <div class="small" style="margin-bottom:8px">所有文件仅保存在项目数据目录；导入顺序不影响候选排序。</div>
    <div id="sources"></div>

    <h2 style="margin-top:16px">资源预算</h2>
    <div class="bgrid">
      <span>delta 深度上限</span><input id="b_depth" type="number"/>
      <span>总展开字节</span><input id="b_total" type="number"/>
      <span>单对象比例</span><input id="b_ratio" type="number" step="0.05"/>
      <span>单对象绝对上限</span><input id="b_obj" type="number"/>
    </div>
    <div class="row" style="margin-top:8px">
      <button onclick="saveBudget()">保存并重算</button>
      <button onclick="retry()">重试暂停对象</button>
    </div>
    <div id="budgetinfo" class="small"></div>

    <h2 style="margin-top:16px">分析分支（冲突来源固定）</h2>
    <div class="row">
      <input id="br_name" placeholder="新分支名"/>
      <button onclick="createBranch()">从当前快照创建</button>
    </div>
    <div id="branches"></div>
  </div>

  <div class="panel" id="center">
    <h2>对象状态 <span id="counts" class="small"></span></h2>
    <div class="row">
      <input id="filter" placeholder="按 oid / 类型 / 状态过滤" oninput="renderObjects()" style="flex:1"/>
      <select id="statusf" onchange="renderObjects()">
        <option value="">全部状态</option>
        <option value="complete">complete</option>
        <option value="blocked">blocked</option>
        <option value="paused">paused</option>
        <option value="error">error</option>
        <option value="fresh">fresh</option>
      </select>
    </div>
    <div style="max-height:230px;overflow:auto">
      <table id="objtable"><thead><tr>
        <th>id</th><th>类型</th><th>oid(前缀)</th><th>状态</th><th>大小</th><th>base</th><th>来源</th><th>证据</th>
      </tr></thead><tbody></tbody></table>
    </div>

    <h2 style="margin-top:14px">Pack 布局（原始偏移）</h2>
    <div id="layout"></div>
    <div class="legend">
      <span><i style="background:#3fb950"></i>blob/tree/commit/tag</span>
      <span><i style="background:#bc8cff"></i>ofs-delta</span>
      <span><i style="background:#58a6ff"></i>ref-delta</span>
      <span><i style="background:#f85149"></i>解析错误</span>
      <span><i style="background:#d29922"></i>CRC/大小异常</span>
    </div>

    <h2 style="margin-top:14px">delta DAG</h2>
    <svg class="dag" id="dag">
      <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#58a6ff"/></marker></defs>
      <g id="dagedges"></g><g id="dagnodes"></g>
    </svg>
  </div>

  <div class="panel" id="right">
    <h2>对象详情 / 内容预览</h2>
    <div id="detail" class="muted">点击中间任一对象查看：重算 oid、原始偏移、delta 指令范围、阻塞链与错误证据。</div>
  </div>
</div>
<div id="toast"></div>

<script>
let STATE=null, SELECTED=null;
const $=s=>document.querySelector(s);
function toast(t){const el=$('#toast');el.textContent=t;el.style.display='block';clearTimeout(el._t);el._t=setTimeout(()=>el.style.display='none',4000);}
async function api(path,opt){const r=await fetch(path,opt);const j=await r.json().catch(()=>({}));if(!r.ok)toast((j.error||r.status)+'');return j;}
function bytes(n){if(n==null)return '-';const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<3){n/=1024;i++;}return (i?n.toFixed(1):n)+u[i];}
function pill(s){return '<span class="pill '+s+'">'+s+'</span>';}
function oid8(o){return o?o.slice(0,10):'<span class=muted>—</span>';}

async function refresh(){STATE=await api('/api/state');renderAll();}
function renderAll(){renderSources();renderObjects();renderBudget();renderBranches();renderLayout();renderDag();if(SELECTED)showObject(SELECTED);}
function renderSources(){
  $('#sources').innerHTML=STATE.sources.map(s=>`
    <div class="src" onclick="sourceDetail(${s.id})">
      <div><b>${s.kind}</b> · <span class="mono">${s.filename}</span></div>
      <div class="small">${bytes(s.size_bytes)} · sha1 ${s.sha1.slice(0,12)}…
      ${s.pack_checksum?'<br>pack校验和 '+s.pack_checksum.slice(0,12)+'…':''}
      ${s.idx_pack_checksum?'<br>idx→pack '+s.idx_pack_checksum.slice(0,12)+'…':''}</div>
      <div class="small">${s.evidence.length?'<span style="color:var(--err)">⚠ '+s.evidence.length+' 条证据</span>':'<span style="color:var(--ok)">无结构异常</span>'}
      &nbsp;<button onclick="event.stopPropagation();askDelete(${s.id})">删除前检查依赖</button></div>
    </div>`).join('') || '<div class="muted">尚未导入文件</div>';
}
function renderBudget(){
  const b=STATE.budget;
  $('#b_depth').value=b.max_depth;$('#b_total').value=b.max_total_bytes;
  $('#b_ratio').value=b.max_obj_ratio;$('#b_obj').value=b.max_obj_bytes;
  $('#budgetinfo').innerHTML='已完成对象累计展开：'+bytes(b.used_total_bytes)+' / '+bytes(b.max_total_bytes);
  $('#budgetline').textContent='预算：深度 '+b.max_depth+' · 总量 '+bytes(b.max_total_bytes)+' · 已用 '+bytes(b.used_total_bytes);
}
async function saveBudget(){
  await api('/api/budget',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    max_depth:+$('#b_depth').value,max_total_bytes:+$('#b_total').value,
    max_obj_ratio:+$('#b_ratio').value,max_obj_bytes:+$('#b_obj').value})});
  refresh();
}
async function retry(){await api('/api/retry',{method:'POST'});refresh();}
function renderBranches(){
  $('#branches').innerHTML=STATE.branches.map(b=>`<div class="small" style="padding:3px 0">• ${b.name}${b.name===STATE.branch?' (当前)':''}
    <span class=muted>${b.publishedPins||''}</span></div>`).join('');
}
async function createBranch(){
  const name=$('#br_name').value.trim();if(!name)return toast('请填写分支名');
  await api('/api/branches',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,from:STATE.branch})});
  $('#br_name').value='';toast('已创建分析分支 '+name);refresh();
}

function renderObjects(){
  if(!STATE)return;
  const f=$('#filter').value.toLowerCase(), sf=$('#statusf').value;
  const rows=STATE.objects.filter(o=>{
    if(sf&&o.status!==sf)return false;
    if(!f)return true;
    return [o.oid,o.stype,o.final_type,o.status,o.base_oid,'#'+o.id].filter(Boolean).join(' ').toLowerCase().includes(f);
  });
  $('#objtable').querySelector('tbody').innerHTML=rows.map(o=>`
    <tr class="obj ${SELECTED===o.id?'sel':''}" onclick="showObject(${o.id})">
      <td class="mono">${o.id}</td>
      <td>${o.final_type||o.stype}${o.delta?' <span class="muted">δ</span>':''}${o.same_oid_candidates>1?' ⧉':''}</td>
      <td class="mono">${oid8(o.oid)}</td>
      <td>${pill(o.status)}</td>
      <td class="mono">${bytes(o.body_len??o.inflated_size)}</td>
      <td class="mono small">${o.base_oid?o.base_oid.slice(0,8):(o.base_offset!=null?'@'+o.base_offset:'—')}</td>
      <td class="mono">#${o.source_id}</td>
      <td>${o.evidence.length?'<span style="color:var(--err)">'+o.evidence.length+'</span>':'<span style="color:var(--ok)">0</span>'}</td>
    </tr>`).join('');
  const c=STATE.counts||{};
  $('#counts').textContent=`共 ${STATE.objects.length} 个候选 · ✓${c.complete||0} 阻${c.blocked||0} 停${c.paused||0} 错${c.error||0} 新${c.fresh||0}`;
}

function renderLayout(){
  const packs=STATE.sources.filter(s=>s.kind==='pack');
  if(!packs.length){$('#layout').innerHTML='<div class="muted">无 pack</div>';return;}
  const objs=STATE.objects.filter(o=>o.pack_offset!=null);
  const total=Math.max(...STATE.sources.filter(s=>s.kind==='pack').map(s=>s.size_bytes),1);
  const bySrc={};STATE.sources.forEach(s=>bySrc[s.id]=s);
  $('#layout').innerHTML=packs.map(s=>{
    const list=objs.filter(o=>o.source_id===s.id).sort((a,b)=>a.pack_offset-b.pack_offset);
    return `<div style="margin-bottom:10px">
      <div class="small">${s.filename}（${bytes(s.size_bytes)}）${s.evidence.length?' <span style="color:var(--err)">⚠ '+s.evidence[0].code+'</span>':''}</div>
      <div class="layout">${list.map(o=>{
        const w=Math.max(4,Math.round(((o.inflated_size||o.declared_size||1)/Math.max(s.size_bytes,1))*260));
        const col=o.evidence.length?'#f85149':(o.stype==='ofs_delta'?'#bc8cff':o.stype==='ref_delta'?'#58a6ff':'#3fb950');
        return `<div class="lblock" style="height:${14+(o.depthN||0)}px;width:${Math.max(w,10)}px;background:${col}"
          title="#${o.id} @${o.pack_offset} ${o.stype} 声明${o.declared_size} 解压${o.inflated_size??'—'} ${o.status}"
          onclick="showObject(${o.id})"></div>`;
      }).join('')}</div></div>`;
  }).join('');
}
function renderDag(){
  const svg=$('#dag'), NS='http://www.w3.org/2000/svg';
  $('#dagedges').innerHTML='';$('#dagnodes').innerHTML='';
  const objs=STATE.objects;
  // 布局：按 delta 深度分层（base 在左）
  const depth={}, idmap={};objs.forEach(o=>idmap[o.id]=o);
  function d(o,seen=new Set()){
    if(depth[o.id]!=null)return depth[o.id];
    if(seen.has(o.id))return 0;seen.add(o.id);
    let dd=0;
    STATE.edges.forEach(e=>{if(e.from===o.id&&idmap[e.to])dd=Math.max(dd,d(idmap[e.to],seen)+1);});
    depth[o.id]=dd;return dd;
  }
  objs.forEach(o=>d(o));
  const levels={};
  objs.forEach(o=>{const lv=depth[o.id]||0;(levels[lv]=levels[lv]||[]).push(o);});
  const pos={};const lvs=Object.keys(levels).map(Number).sort((a,b)=>a-b);
  lvs.forEach(lv=>levels[lv].forEach((o,i)=>pos[o.id]={x:30+lv*130,y:20+i*40}));
  const color={complete:'#3fb950',blocked:'#d29922',paused:'#bc8cff',error:'#f85149',fresh:'#5b6470'};
  STATE.edges.forEach(e=>{
    const a=pos[e.from],b=pos[e.to];if(!a||!b)return;
    const p=document.createElementNS(NS,'path');
    p.setAttribute('class','edge '+(e.ref_kind==='ref_delta'?'delta':''));
    p.setAttribute('d',`M${a.x+70},${a.y+9} C${a.x+100},${a.y+9} ${b.x-30},${b.y+9} ${b.x},${b.y+9}`);
    $('#dagedges').appendChild(p);
  });
  objs.forEach(o=>{
    const p=pos[o.id];if(!p)return;
    const g=document.createElementNS(NS,'g');g.setAttribute('class','node');
    g.setAttribute('transform',`translate(${p.x},${p.y})`);
    g.innerHTML=`<rect width="74" height="18" rx="3" fill="#161b22" stroke="${color[o.status]||'#5b6470'}"/>
      <text x="4" y="13">#${o.id} ${(o.final_type||o.stype).slice(0,4)}</text>`;
    g.addEventListener('click',()=>showObject(o.id));
    $('#dagnodes').appendChild(g);
  });
}

async function showObject(id){
  SELECTED=id;renderObjects();
  const o=await api('/api/objects/'+id);
  if(o.error)return;
  const ev=[...(o.evidence||[])].map(e=>`<div class="ev ${/mismatch|crc|spoof|truncated|range|环|越界/.test(e.message)?'':'warn'}">
    <span class="code">${e.code}</span> · 偏移 ${e.offset??'—'} 长度 ${e.len??'—'}<br>${e.message}</div>`).join('');
  const blocked=(o.blocked_chain||[]).map(h=>`<div class="ev warn"><span class="code">阻塞链</span>
     候选 #${h.candidate_id}(${h.stype}) ${h.base_ref||''} → ${h.reason}</div>`).join('');
  const pause=o.pause&&o.pause.kind?`<div class="ev warn"><span class="code">可重试暂停</span>
     ${o.pause.detail?.reason||o.pause.kind}<br><span class=small>${o.pause.detail?.hint||''} 声明目标 ${o.pause.detail?.declared_target_size||''} 深度 ${o.pause.detail?.depth||''}</span></div>`:'';
  const steps=(o.steps||[]).map(s=>`<div class="step ${s.ok?'':'bad'}">
    <span class=k>${s.kind}</span> op[${s.op_start}..+${s.op_len}] src=${s.src_offset} len=${s.length}
    out ${s.out_before}→${s.out_after} ${s.ok?'✓':'✗ '+ (s.note||'')} <span class=small>(depth ${s.depth}, base#${s.base_candidate_id??'?'})</span></div>`).join('');
  const sameOid=STATE.objects.filter(x=>x.oid&&o.oid&&x.oid===o.oid&&!x.delta);
  const pin=sameOid.length>1?`<div class="row" style="margin-top:8px">
     <label class="small">同一 oid 有 ${sameOid.length} 个候选，固定来源：</label>
     <select id="pinsel">${sameOid.map(x=>`<option value="${x.id}" ${x.id===id?'selected':''}>#${x.id} 来源#${x.source_id} 偏移${x.pack_offset??'loose'} ${x.evidence.length}⚠</option>`).join('')}</select>
     <button onclick="pinOid('${o.oid}')">生成分支并固定</button></div>`:'';
  $('#detail').innerHTML=`
    <div class="row"><b>#${o.id}</b> ${(o.final_type||o.stype)} ${pill(o.status)}
       <span class="mono small">${o.oid||''}</span></div>
    <div class="small">来源 #${o.source_id} · pack 偏移 ${o.pack_offset??'—'} · 压缩[${o.pack_offset??0}+header, len=${'—'}]
       <br>声明 ${o.declared_size} · 解压 ${o.inflated_size??'—'} · body ${o.body_len} · delta 指令 ${o.delta_len} 字节</div>
    ${o.base_oid?`<div class="small">ref-delta base: <span class=mono>${o.base_oid}</span></div>`:''}
    ${o.base_offset!=null?`<div class="small">ofs-delta base 偏移: <span class=mono>${o.base_offset}</span></div>`:''}
    ${pin}
    <details ${blocked||pause?'open':''}><summary>阻塞链 / 暂停</summary>${blocked}${pause||'<div class=muted>无</div>'}</details>
    <details open><summary>内容预览（重算 oid 已在上方展示）</summary>
      <pre>${o.body_preview&&o.body_preview.is_text?escapeHtml(o.body_preview.text||''):(o.body_preview?'(二进制，hex 预览)':'(无完整 body：对象未还原)')}</pre>
      ${o.body_preview&&!o.body_preview.is_text?`<pre>${o.body_preview.hex.slice(0,800)}</pre>`:''}
      <div class="small">body sha1(内容指纹)=${o.body_sha1} · 显示 ${o.body_preview?.shown_bytes||0} 字节 ${o.body_preview?.truncated?'（已截断）':''}</div>
    </details>
    ${o.delta_len?`<details open><summary>delta 指令逐步记录（base / 指令范围 / 输入输出长度 / 校验）</summary><div>${steps||'<div class=muted>无（可能尚未应用或被预算暂停）</div>'}</div>
      <div class=small>delta 字节指纹 ${o.delta_sha1} · hex ${o.delta_preview_hex.slice(0,160)}…</div></details>`:''}
    <details ${ev?'open':''}><summary>错误证据 (${(o.evidence||[]).length})</summary>${ev||'<div class=muted>无</div>'}</details>`;
}
function escapeHtml(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

async function pinOid(oid){
  const cid=+$('#pinsel').value;
  let name=prompt('新分析分支名（固定该 oid 的来源）','pin-'+oid.slice(0,7));
  if(!name)return;
  await api('/api/branches',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name,from:STATE.branch,pinned:{[oid]:cid}})});
  toast('已创建分支 '+name+' 并固定 #'+cid);refresh();
}

async function upload(){
  const files=$('#file').files;if(!files.length)return toast('先选择文件');
  const fd=new FormData();for(const f of files)fd.append('files',f,f.name);
  const r=await fetch('/api/import',{method:'POST',body:fd});const j=await r.json();
  if(j.imported){j.imported.forEach(rep=>{
    const rs=rep.resolve;
    toast(`已导入 ${rep.filename}：${rep.objects} 对象`+(rs?` · ✓${rs.complete} 阻${rs.blocked} 停${rs.paused} 错${rs.error}`:''));
  });}
  $('#file').value='';refresh();
}
async function sourceDetail(id){const s=await api('/api/sources/'+id);toast(s.filename+' sha1='+s.sha1);}
async function askDelete(id){
  const d=await api('/api/sources/'+id+'/dependents');
  if(d.can_delete){
    if(confirm('没有对象依赖该源文件，确认删除？')){await fetch('/api/sources/'+id,{method:'DELETE'});refresh();}
  }else{
    toast('仍有 '+d.dependents.length+' 个对象依赖该源文件，已阻止删除：#'+d.dependents.map(x=>x.candidate_id).join(', #'));
  }
}
refresh();
</script>
</body></html>
"##;
