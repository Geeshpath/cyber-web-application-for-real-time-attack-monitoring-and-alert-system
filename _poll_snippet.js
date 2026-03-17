/* ═══════════════════════════════════
   REAL BACKEND POLLING
═══════════════════════════════════ */
let _pollTimer=null;
async function pollRealAlerts(){
  clearInterval(_pollTimer);
  _pollTimer=setInterval(async()=>{
    try{
      const hdrs={};
      if(typeof _jwt!=='undefined'&&_jwt)hdrs['Authorization']='Bearer '+_jwt;
      const base=typeof API!=='undefined'?API:'http://localhost:8000';
      const r=await fetch(`${base}/alerts?limit=20`,{headers:hdrs,signal:AbortSignal.timeout(3000)});
      if(!r.ok)return;
      const alerts=await r.json();
      if(!alerts||!alerts.length)return;
      const feed=document.getElementById('alertFeed');if(!feed)return;
      // Only inject newest alerts not already shown
      const existingTs=new Set([...feed.querySelectorAll('.feed-row')].map(r=>r.dataset.ts));
      alerts.slice(0,8).reverse().forEach(a=>{
        if(existingTs.has(a.timestamp))return;
        const sev=a.severity==='critical'?'c':a.severity==='high'?'h':a.severity==='medium'?'m':'l';
        const row=makeAlertRow(a.ip||'unknown',a.pattern_type||'Unknown',sev);
        row.dataset.ts=a.timestamp||'';
        row.onclick=()=>showExplainReal(a);
        feed.insertBefore(row,feed.firstChild);
        while(feed.children.length>20)feed.removeChild(feed.lastChild);
      });
      updateGauges();
    }catch{}
  },4000);
}

async function showExplainReal(alert){
  const p=document.getElementById('explainPanel');
  const t=document.getElementById('explainText');
  const s=document.getElementById('explainSteps');
  if(!p)return;
  p.classList.add('show');
  t.textContent='Asking Sentinel AI…';
  s.innerHTML='';
  try{
    const hdrs={'Content-Type':'application/json'};
    if(typeof _jwt!=='undefined'&&_jwt)hdrs['Authorization']='Bearer '+_jwt;
    const base=typeof API!=='undefined'?API:'http://localhost:8000';
    const r=await fetch(`${base}/explain`,{
      method:'POST',headers:hdrs,
      body:JSON.stringify({
        pattern_type:alert.pattern_type,
        ip:alert.ip,
        event_count:alert.event_count,
        severity:alert.severity,
        timestamp:alert.timestamp
      }),
      signal:AbortSignal.timeout(35000)
    });
    const d=await r.json();
    t.textContent=d.explanation||alert.explanation||'No explanation available.';
    const mitigations=Array.isArray(d.mitigation)?d.mitigation:(d.mitigation?[d.mitigation]:[]);
    s.innerHTML=mitigations.map((st,i)=>`<div class="es"><div class="es-n">${i+1}</div><div>${st}</div></div>`).join('');
  }catch{
    showExplain(alert.ip,alert.pattern_type,alert.severity==='critical'?'c':alert.severity==='high'?'h':'m');
  }
}
