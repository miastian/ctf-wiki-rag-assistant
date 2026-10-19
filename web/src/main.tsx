import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import ReactMarkdown from 'react-markdown';
import './style.css';

type Source = {number:number; id:string; doc_id:string; title:string; section:string; text:string; url:string; source:string; lang:string; version?:string; source_url?:string};
type Settings = {mode:string; sources:string[]; language:string|null; categories?:string[]; quick?:string|null};
type Result = {query?:string; mode?:string; sources?:Source[]; trace?:unknown; error?:string};
type Turn = {id:string; question:string; answer:string; status:string; settings:Settings; result:Result; request_id?:string};
type Session = {id:string; title:string; updated:number; turns?:Turn[]};
type Options = {sources:string[]; languages:string[]; modes:Record<string,string>; profile?:string; ready?:boolean; reason?:string; categories?:string[]; max_input?:number; library?:{commit?:string; documents?:number; chunks?:number}};
const defaults:Settings = {mode:'auto',sources:[],language:null,categories:[]};
const names:Record<string,string> = {'ctf-wiki':'CTF Wiki',zh:'中文',web:'Web',misc:'Misc',reverse:'Reverse',crypto:'Crypto',pwn:'Pwn',ai:'AI',android:'Android',assembly:'汇编',executable:'可执行文件',blockchain:'区块链',ics:'工控',introduction:'CTF 基础'};
type MarkdownNode = {type:string; value?:string; children?:MarkdownNode[]; url?:string};
function citationPlugin(){
  return (tree:MarkdownNode)=>{
    function walk(node:MarkdownNode){
      if(!node.children||node.type==='link')return;
      node.children=node.children.flatMap(child=>{
        if(child.type!=='text'){walk(child);return [child];}
        return (child.value||'').split(/(\[\d+\])/g).filter(Boolean).map(part=>{
          const match=/^\[(\d+)\]$/.exec(part);
          return match?{type:'link',url:'#evidence-'+match[1],children:[{type:'text',value:part}]}:{type:'text',value:part};
        });
      });
    }
    walk(tree);
  };
}

async function api<T>(path:string, init?:RequestInit):Promise<T> {
  const response = await fetch('/api'+path, init);
  if(!response.ok) { const body = await response.json().catch(()=>({})); throw new Error(typeof body.detail==='string'?body.detail:'请求未完成，请检查服务状态。'); }
  return response.json();
}

function App(){
  const [sessions,setSessions]=useState<Session[]>([]), [active,setActive]=useState<Session|null>(null);
  const [options,setOptions]=useState<Options>({sources:[],languages:[],modes:{auto:'自动'}});
  const [settings,setSettings]=useState<Settings>(defaults),[draft,setDraft]=useState('');
  const [busy,setBusy]=useState(false),[stage,setStage]=useState(''),[error,setError]=useState(''),[ready,setReady]=useState(false);
  const [evidence,setEvidence]=useState<Source|null>(null),[debug,setDebug]=useState(false),[copied,setCopied]=useState('');
  const end=useRef<HTMLDivElement>(null);
  const refresh=async()=>setSessions(await api<Session[]>('/sessions'));
  async function select(id:string){
    const session=await api<Session>('/sessions/'+id); setActive(session);setEvidence(null);setError('');
    const last=session.turns?.at(-1);setSettings(last?{...last.settings,quick:null}:defaults);
  }
  useEffect(()=>{(async()=>{
    try {const rows=await api<Session[]>('/sessions');setSessions(rows);if(rows.length)await select(rows[0].id);
      const loaded=await api<Options>('/options');setOptions(loaded);setReady(loaded.ready!==false);
      if(loaded.ready===false)setError(loaded.reason||'知识库尚未就绪');
    }catch(exc){setError((exc as Error).message);}
  })();},[]);
  useEffect(()=>{end.current?.scrollIntoView({behavior:'smooth',block:'end'});},[active?.turns?.at(-1)?.answer,stage]);
  async function fresh(){try{const s=await api<Session>('/sessions',{method:'POST'});setActive(s);setSettings(defaults);setEvidence(null);setError('');await refresh();}catch(exc){setError((exc as Error).message);}}
  async function remove(clear:boolean){
    if(!active||!window.confirm(clear?'清空此会话的全部消息？':'删除此会话及全部消息？'))return;
    try{await api('/sessions/'+active.id+(clear?'/clear':''),{method:clear?'POST':'DELETE'});
      setEvidence(null);setSettings(defaults);if(clear)await select(active.id);else setActive(null);await refresh();
    }catch(exc){setError((exc as Error).message);}
  }
  async function send(question=draft, override?:Settings){
    if(busy||!ready||!question.trim())return;
    setBusy(true);setError('');setEvidence(null);setStage('准备会话');setDraft('');
    let sid=active?.id;
    const request_id=crypto.randomUUID(), chosen={...(override||settings)};
    try{
      if(!sid){const s=await api<Session>('/sessions',{method:'POST'});sid=s.id;setActive(s);}
      const current=await api<Session>('/sessions/'+sid);
      const pending:Turn={id:request_id,request_id,question,answer:'',status:'running',settings:chosen,result:{}};
      setActive({...current,turns:[...(current.turns||[]),pending]});
      const response=await fetch('/api/sessions/'+sid+'/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question,request_id,...chosen})});
      if(!response.ok){const body=await response.json();throw new Error(typeof body.detail==='string'?body.detail:'请求未完成');}
      if(!response.body)throw new Error('浏览器未提供响应流');
      const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='',finished=false;
      while(true){const chunk=await reader.read();buffer+=decoder.decode(chunk.value,{stream:!chunk.done});
        let split:number;
        while((split=buffer.indexOf('\n\n'))>=0){
          const frame=buffer.slice(0,split);buffer=buffer.slice(split+2);
          const type=frame.split('\n').find(l=>l.startsWith('event: '))?.slice(7);
          const dataLine=frame.split('\n').find(l=>l.startsWith('data: '));if(!dataLine)continue;
          const data=JSON.parse(dataLine.slice(6));
          if(type==='stage')setStage(data.label);
          if(type==='delta')setActive(s=>s?{...s,turns:s.turns?.map(t=>t.request_id===request_id?{...t,answer:t.answer+data.text}:t)}:s);
          if(type==='done'){finished=true;setActive(s=>s?{...s,turns:s.turns?.map(t=>t.request_id===request_id?{...t,answer:data.answer,status:'complete',result:data}:t)}:s);}
          if(type==='error')throw new Error(data.error||'本轮未完成，可手动重试。');
        }
        if(chunk.done)break;
      }
      if(!finished)throw new Error('连接中断，本轮未完成。请稍后刷新并重试。');
    }catch(exc){setError((exc as Error).message);}
    finally{
      if(sid)try{setActive(await api<Session>('/sessions/'+sid));}catch{}
      try{await refresh();}catch{}
      setBusy(false);setStage('');
    }
  }
  function cite(text:string, sources:Source[]){return <ReactMarkdown remarkPlugins={[citationPlugin]} components={{a:({href,children})=>{
    const n=/^#evidence-(\d+)$/.exec(href||''), source=n?sources.find(s=>s.number===Number(n[1])):undefined;
    if(source)return <button className="cite" onClick={()=>setEvidence(source)} aria-label={'查看引用 '+source.number}>{children}</button>;
    return n?<>{children}</>:<a href={/^https?:\/\//i.test(href||'')?href:undefined} target="_blank" rel="noreferrer">{children}</a>;
  }}}>{text}</ReactMarkdown>;}
  const turns=active?.turns||[];
  const displayedExamples=['PNG 隐写题通常从哪些方向检查？','拿到一个 ELF 逆向题，应该先分析什么？','SQL 注入题中，如何根据响应差异确定分析方向？'];
  const categoryChoices=options.categories||[];
  const selectedCategories=settings.categories||[];
  const lastCompleteId=turns.filter(t=>t.status==='complete').at(-1)?.id;
  return <div className={'workspace '+(evidence?'with-evidence':'')}>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">C/</span><div>CTF 思路助手<small>对话工作台</small></div></div>
      <button className="new-chat" disabled={busy} onClick={fresh}>＋ 新建会话</button>
      <select className="mobile-sessions" aria-label="选择历史会话" value={active?.id||''} disabled={busy} onChange={e=>e.target.value&&select(e.target.value).catch(e=>setError(e.message))}><option value="">历史会话</option>{sessions.map(s=><option key={s.id} value={s.id}>{s.title}</option>)}</select>
      <p className="eyebrow">本机会话 <span>{sessions.length}</span></p>
      <nav aria-label="历史会话">{sessions.map(s=><button key={s.id} className={'session '+(active?.id===s.id?'selected':'')} disabled={busy} onClick={()=>select(s.id).catch(e=>setError(e.message))}>{s.title}<small>{new Date(s.updated*1000).toLocaleDateString('zh-CN')}</small></button>)}</nav>
      <div className="sidebar-foot"><span className="status-dot"/>历史记录保存在本机<br/><small>答案附依据，条件需核实</small></div>
    </aside>
    <main>
      <header><div><span className="eyebrow">CTF WIKI · LEARN & EXPLORE</span><h1>{active?.title==='新会话'?'开始一次有依据的问答':active?.title||'带着线索，找到下一步'}</h1></div><div className="header-actions"><label><input type="checkbox" checked={debug} onChange={e=>setDebug(e.target.checked)}/> 调试</label><button disabled={!active||busy} onClick={()=>remove(true)}>清空</button><button className="danger" disabled={!active||busy} onClick={()=>remove(false)}>删除</button></div></header>
      <section className="toolbar" aria-label="回答设置">
        <label>回答形式<select aria-label="回答形式" disabled={busy} value={settings.mode} onChange={e=>setSettings({...settings,mode:e.target.value})}>{Object.entries(options.modes).map(([key,label])=><option key={key} value={key}>{label}</option>)}</select></label>
      <details className="filter"><summary>题目方向 · {selectedCategories.length?selectedCategories.length+' 项':'全部'}</summary><div className="filter-menu">{categoryChoices.map(category=><label key={category}><input type="checkbox" disabled={busy} checked={selectedCategories.includes(category)} onChange={e=>setSettings({...settings,categories:e.target.checked?[...selectedCategories,category]:selectedCategories.filter(s=>s!==category)})}/>{names[category]||category}</label>)}</div></details>
        <details className="filter"><summary>资料来源 · {settings.sources.length?settings.sources.length+' 项':'全部'}</summary><div className="filter-menu">{options.sources.map(source=><label key={source}><input type="checkbox" disabled={busy} checked={settings.sources.includes(source)} onChange={e=>setSettings({...settings,sources:e.target.checked?[...settings.sources,source]:settings.sources.filter(s=>s!==source)})}/>{names[source]||source}</label>)}</div></details>
        <label>语言<select aria-label="资料语言" disabled={busy} value={settings.language||''} onChange={e=>setSettings({...settings,language:e.target.value||null})}><option value="">全部语言</option>{options.languages.map(l=><option key={l} value={l}>{names[l]||l}</option>)}</select></label>
        <button className="reset-filter" disabled={busy} onClick={()=>setSettings({...settings,sources:[],language:null,categories:[]})}>清除筛选</button>
      </section>
      <div className="range">检索范围：{selectedCategories.length?selectedCategories.map(s=>names[s]||s).join('、'):'CTF Wiki 全部方向'} · {settings.language?names[settings.language]||settings.language:'全部语言'}<span role="status">{ready?'设置仅影响后续提问':error?'知识库尚未就绪':'正在加载知识库…'}</span></div>
      <div className="library-note">{ready?`${options.library?.documents??'—'} 篇资料 · ${options.library?.commit?.slice(0,8)||'版本未提供'}`:'CTF 资料尚未构建导入'} · 文字资料检索，图片内容未提取 · {ready?'粘贴题面和工具结果即可开始':'远程构建并导入后可开始提问'}</div>
      <section className="messages" aria-label="会话消息" aria-live="polite">
        {!turns.length&&<div className="welcome"><div className="welcome-symbol">?</div><p className="eyebrow">从一个具体问题开始</p><h2>读懂线索，<br/>找到分析的下一步。</h2><p>问常见做法，或贴出题面、代码和工具输出。<br/>先给提示，再根据你的反馈逐步展开。</p><div className="examples">{displayedExamples.map(q=><button disabled={busy||!ready} key={q} onClick={()=>send(q)}>{q}<span>↗</span></button>)}</div></div>}
        {turns.map(turn=><article key={turn.id} className="turn"><div className="user-question"><span className="message-label">你</span><p>{turn.question}</p></div><div className="assistant-answer"><div className="answer-heading"><span className="assistant-icon">S</span><span>知识库助手</span><span className="answer-mode">{options.modes[turn.result.mode||turn.settings.mode]||'自动'}</span></div><div className="answer-text">{cite(turn.answer,turn.result.sources||[])}</div>
          {(turn.result.sources?.length||0)>0&&<div className="source-list"><span className="eyebrow">本轮依据</span>{turn.result.sources?.map(s=><button key={s.number} onClick={()=>setEvidence(s)}>[{s.number}] {s.title}{s.section?' / '+s.section:''}</button>)}</div>}
          {turn.status==='complete'&&<div className="answer-actions">{turn.id===lastCompleteId&&<>{[['why','为什么这样查'],['next','下一步怎么做'],['steps','展开详细步骤'],['summary','总结已尝试的方法']].map(([key,label])=><button disabled={busy||!ready} key={key} onClick={()=>send(label,{...settings,quick:key})}>{label}</button>)}</>}<button onClick={async()=>{try{await navigator.clipboard.writeText(turn.answer);setCopied(turn.id);}catch{setError('复制失败，请手动选择答案复制。');}}}>{copied===turn.id?'已复制':'复制答案'}</button></div>}
          {turn.status!=='complete'&&turn.status!=='running'&&<div className="failed">{turn.result.error||'本轮未完成。'} 未加入有效对话上下文。<button disabled={busy} onClick={()=>send(turn.question,turn.settings)}>重试本轮</button></div>}
          {turn.status==='running'&&!busy&&<div className="failed">请求仍在处理。<button onClick={()=>active&&select(active.id)}>刷新状态</button></div>}
          {debug&&<details className="debug"><summary>查看检索过程</summary><pre>{JSON.stringify(turn.result,null,2)}</pre></details>}
        </div></article>)}
        {busy&&<div className="progress"><span className="pulse"/>{stage}…</div>}<div ref={end}/>
      </section>
      <footer className="composer-area">{error&&<div role="alert" className="error">{error} {!ready&&<button onClick={()=>window.location.reload()}>重新加载</button>}</div>}
        <form className="composer" onSubmit={e=>{e.preventDefault();send();}}><textarea aria-label="输入问题" value={draft} disabled={busy} onChange={e=>setDraft(e.target.value)} maxLength={options.max_input||16000} placeholder="粘贴题面、代码或工具结果，或询问某类题的常见做法…" onKeyDown={e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.nativeEvent.isComposing){e.preventDefault();send();}}}/><button className="send" disabled={busy||!ready||!draft.trim()} type="submit">{busy?'回答中':'发送 ↑'}</button></form><p>Enter 发送 · Shift + Enter 换行<span>方法有来源，推测待验证 · 不自动执行工具</span></p>
      </footer>
    </main>
    {evidence&&<aside className="evidence"><div className="evidence-header"><span className="eyebrow">引用原文 / {evidence.number}</span><button aria-label="关闭引用" onClick={()=>setEvidence(null)}>×</button></div><span className="source-tag">{names[evidence.source]||evidence.source}</span><h2>{evidence.title}</h2><p>{evidence.section}</p><code>{evidence.id}</code>{evidence.version&&<p>资料版本：{evidence.version.slice(0,12)}</p>}<pre>{evidence.text}</pre>{/^https?:\/\//i.test(evidence.url)&&<a href={evidence.url} target="_blank" rel="noreferrer">打开资料来源 ↗</a>}{evidence.source_url&&/^https?:\/\//i.test(evidence.source_url)&&<p><a href={evidence.source_url} target="_blank" rel="noreferrer">查看固定版本原文 ↗</a></p>}<small>保存的是该轮用于回答的证据片段。</small></aside>}
  </div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
