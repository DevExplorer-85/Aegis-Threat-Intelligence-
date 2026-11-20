(() => {
  const api = location.port === "8000" ? location.origin : "http://127.0.0.1:8000";
  const token = () => localStorage.getItem("cti_auth_token");
  const $ = (id) => document.getElementById(id);
  let members = [];
  function showNotice(message, error=false) { const el=$('notice'); el.textContent=message; el.className=`c15-notice ${error?'error':''}`; el.hidden=false; }
  async function request(path, options={}) {
    const headers={ ...(options.headers||{}), ...(token()?{Authorization:`Bearer ${token()}`}:{}) };
    if (options.body) headers['Content-Type']='application/json';
    const res=await fetch(`${api}${path}`, {...options,headers});
    let data={}; try {data=await res.json();} catch {}
    if (!res.ok) {
      const detail=data.detail;
      if (res.status===429) throw new Error(typeof detail==='object' ? `${detail.message} (limit ${detail.limit}/min; retry in ${detail.retry_after}s)` : `Rate limit reached. Retry in ${res.headers.get('Retry-After')||'a moment'}.`);
      throw new Error(typeof detail==='string'?detail:detail?.message||`Request failed (${res.status})`);
    }
    return data;
  }
  async function loadMembers() {
    const data=await request('/api/cases/org/members'); members=data.members||[];
    const select=document.querySelector('[name=assignee_id]'); select.innerHTML='<option value="">Unassigned</option>'+members.map(m=>`<option value="${esc(m.user_id)}">${esc(m.name)} · ${esc(m.role)}</option>`).join('');
    $('member-list').innerHTML=members.length?members.map(m=>`<div class="c15-member"><b>${esc(m.name)}</b><span>${esc(m.email||m.user_id)}</span><i>${esc(m.role)}</i></div>`).join(''):'<div class="c15-empty">No members found.</div>';
  }
  function esc(v='') { const d=document.createElement('span'); d.textContent=String(v); return d.innerHTML; }
  function render(cases) {
    const list=$('case-list');
    if(!cases.length){list.innerHTML='<div class="c15-empty">No cases match these filters. Create a case to start an investigation.</div>';return;}
    list.innerHTML=cases.map(c=>`<article class="c15-case" data-id="${esc(c.case_id)}"><div class="c15-case-top"><div><span class="c15-severity ${esc(c.severity)}">${esc(c.severity)}</span><span class="c15-case-date">Updated ${esc(new Date(c.updated_at).toLocaleString())}</span></div><select class="case-status" aria-label="Update status"><option ${c.status==='Open'?'selected':''}>Open</option><option ${c.status==='In Progress'?'selected':''}>In Progress</option><option ${c.status==='Closed'?'selected':''}>Closed</option></select></div><h3>${esc(c.title)}</h3><p>${esc(c.description||'No investigation notes yet.')}</p><div class="c15-case-meta"><span>Created by ${esc(c.created_by_name||'member')}</span><span>${c.assignee_id?`Assigned to ${esc(members.find(m=>m.user_id===c.assignee_id)?.name||c.assignee_id)}`:'Unassigned'}</span>${c.linked_event?`<span>Event ${esc(c.linked_event.event_uuid)}</span>`:''}${c.linked_threat?`<span>Threat report ${esc(c.linked_threat.report_id)}</span>`:''}</div></article>`).join('');
    list.querySelectorAll('.case-status').forEach(sel=>sel.addEventListener('change',async e=>{const card=e.target.closest('.c15-case');try{await request(`/api/cases/${encodeURIComponent(card.dataset.id)}`,{method:'PATCH',body:JSON.stringify({status:e.target.value})});showNotice('Case status updated.');}catch(err){showNotice(err.message,true);loadCases();}}));
  }
  async function loadCases() {
    try {const p=new URLSearchParams(); if($('status-filter').value)p.set('status_filter',$('status-filter').value);if($('search').value.trim())p.set('q',$('search').value.trim());const data=await request(`/api/cases?${p}`);render(data.cases||[]);}
    catch(err){$('case-list').innerHTML=`<div class="c15-empty">${esc(err.message)}<br><br>Sign in first, then refresh. Demo: admin@cti.platform / admin123 or analyst@cti.platform / analyst123.</div>`;}
  }
  async function init() {
    const prefill=new URLSearchParams(location.search);
    try {const data=await request('/api/cases/me');const org=data.organization||{};$('org-badge').textContent=`${org.name||'Workspace'} · ${data.role||'member'}`;$('scope-title').textContent=data.role==='member'?'Your cases':'All cases of the organisation';$('scope-subtitle').textContent=data.role==='member'?'Cases assigned to you or created by you.':'Cases visible to your organization role.';await loadMembers();}
    catch(err){$('org-badge').textContent='Sign in required';showNotice(err.message,true);}
    if(prefill.get('feed_id')||prefill.get('event_uuid')||prefill.get('report_id')){$('case-form-wrap').hidden=false;document.querySelector('[name=feed_id]').value=prefill.get('feed_id')||'';document.querySelector('[name=event_uuid]').value=prefill.get('event_uuid')||'';document.querySelector('[name=report_id]').value=prefill.get('report_id')||'';}
    await loadCases();
  }
  $('new-case').onclick=()=>$('case-form-wrap').hidden=!$('case-form-wrap').hidden;
  $('cancel-case').onclick=()=>$('case-form-wrap').hidden=true;
  $('refresh').onclick=loadCases;
  $('status-filter').onchange=loadCases;
  let timer; $('search').oninput=()=>{clearTimeout(timer);timer=setTimeout(loadCases,250);};
  $('load-members').onclick=()=>loadMembers().catch(e=>showNotice(e.message,true));
  $('members-tab').onclick=()=>setTimeout(()=>$('members').scrollIntoView({behavior:'smooth'}),0);
  $('case-form').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.currentTarget);const body={title:f.get('title'),description:f.get('description'),severity:f.get('severity')};if(f.get('assignee_id'))body.assignee_id=f.get('assignee_id');if(f.get('feed_id')||f.get('event_uuid'))body.linked_event={feed_id:f.get('feed_id'),event_uuid:f.get('event_uuid')};if(f.get('report_id'))body.linked_threat={report_id:f.get('report_id')};try{await request('/api/cases',{method:'POST',body:JSON.stringify(body)});e.currentTarget.reset();$('case-form-wrap').hidden=true;showNotice('Case created successfully.');await loadCases();}catch(err){showNotice(err.message,true);}};
  init();
})();
