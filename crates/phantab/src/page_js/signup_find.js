()=>{
  // phantab's own (browser_sign_up): the sign-up form's new-password fields. Through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <input name=getAttribute> shadows.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,attr=Element.prototype.getAttribute,contains=Node.prototype.contains,rootOf=Node.prototype.getRootNode,shadowOf=get(Element.prototype,'shadowRoot'),hostOf=get(ShadowRoot.prototype,'host'),baseOf=get(Node.prototype,'baseURI'),doc=k=>get(Document.prototype,k).call(document);
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s),hostAbove=n=>{const r=rootOf.call(n);return r instanceof ShadowRoot?hostOf.call(r):null;};
  const tagOf=get(Element.prototype,'tagName'),connected=get(Node.prototype,'isConnected'),closest=Element.prototype.closest,visible=Element.prototype.checkVisibility,rectOf=Element.prototype.getBoundingClientRect,inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined,formOf=el=>el instanceof HTMLFormElement?undefined:el.form;
  const walk=()=>{const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}return roots;};
  const all=s=>walk().flatMap(root=>[...qsa(root,s)]);
  const low=(el,n)=>((el?attr.call(el,n):null)||'').toLowerCase();
  const auto=el=>low(el,'autocomplete').split(/\s+/);
  const named=el=>['name','id','placeholder','aria-label'].map(n=>low(el,n)).join(' ');
  const type=el=>low(el,'type')||'text';
  const shows=el=>{
    if(!connected.call(el)||closest.call(el,'[aria-hidden="true"],[inert]')||!visible.call(el,{opacityProperty:true,visibilityProperty:true}))return false;
    const b=rectOf.call(el);return b.width>=2&&b.height>=2&&b.right+scrollX>0&&b.bottom+scrollY>0&&b.left+scrollX<doc('documentElement').scrollWidth;
  };
  const CARD=/(^| )(card.?(number|num|no)|cc.?(number|num|exp)|cvv|cvc)( |$)/;
  const PAY=/\b(pay|payment|book|purchase|place (your |my )?order|buy|check.?out)\b/;
  const JOIN=/sign.?up|regist|create.{0,12}account|new.?account|join|enrol|get.?started/;
  const SIGNIN=/sign.?in|log.?in|log.?on/;
  const inputs=all('input').filter(shows);
  const passwords=inputs.filter(el=>type(el)==='password');
  const fresh=passwords.filter(el=>auto(el).includes('new-password'));
  const first=fresh[0]||passwords[0]||null;
  const form=first?formOf(first)||null:null;
  const mine=el=>(formOf(el)||null)===form;
  const fields=(fresh.length?fresh:passwords).filter(mine);
  const editable=el=>!el.disabled&&!el.readOnly;
  const inside=(box,el)=>{for(let n=el;n;n=hostAbove(n))if(contains.call(box,n))return true;return false;};
  const label=el=>((tagOf.call(el)==='INPUT'?el.value||attr.call(el,'alt'):inner(el))||attr.call(el,'aria-label')||attr.call(el,'title')||'').trim().toLowerCase().slice(0,80);
  const controls=form?all('button,input[type="submit" i],input[type="image" i],[role="button"]').filter(el=>shows(el)&&(formOf(el)===form||inside(form,el))):[];
  const says=[low(form,'id'),low(form,'name'),low(form,'action'),location.pathname.toLowerCase(),(doc('title')||'').toLowerCase(),...controls.map(label)].join(' ');
  const num=(el,n)=>{const v=parseInt(attr.call(el,n)||'',10);return v>0?v:null;};
  const maxes=fields.map(el=>num(el,'maxlength')).filter(Boolean),mins=fields.map(el=>num(el,'minlength')).filter(Boolean);
  const ruled=fields.find(el=>attr.call(el,'passwordrules'));
  const report={fields:fields.length,maxLength:maxes.length?Math.min(...maxes):null,minLength:mins.length?Math.max(...mins):null,rules:ruled?attr.call(ruled,'passwordrules').slice(0,500):null};
  if(!fields.length||fields.some(el=>!editable(el)))report.refuse='no-field';
  else if(all('input,select').some(el=>auto(el).some(t=>t.startsWith('cc-')))||inputs.some(el=>CARD.test(named(el))))report.refuse='card-fields';
  else if(controls.some(el=>PAY.test(label(el))))report.refuse='pay-button';
  else if(passwords.some(el=>mine(el)&&auto(el).includes('current-password'))||fields.length>2)report.refuse='change-password';
  else if(!fresh.length&&fields.length<2&&(!JOIN.test(says)||SIGNIN.test(controls.map(label).join(' '))))report.refuse='sign-in-form';
  else if(form&&low(form,'method')==='get')report.refuse='get-form';
  // By getAttribute, since form.action reads an <input name=action> instead of the attribute. Every place the form can send to: its own action and each submit control's formaction. An action it cannot resolve is a mark the call refuses on.
  const resolve=a=>{if(!a||/^\s*javascript:/i.test(a))return null;try{return new URL(a,baseOf.call(form||document)).href;}catch{return {unresolved:true};}};
  const actions=()=>[form?attr.call(form,'action'):null,...controls.map(el=>attr.call(el,'formaction'))].map(resolve).filter(a=>a!==null);
  report.href=location.href;report.ancestors=[...location.ancestorOrigins];report.actions=actions();
  return {report,fields,form,actions};
}