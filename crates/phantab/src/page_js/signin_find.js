()=>{
  // phantab: through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <input name=getAttribute> shadows.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,attr=Element.prototype.getAttribute,contains=Node.prototype.contains,rootOf=Node.prototype.getRootNode,shadowOf=get(Element.prototype,'shadowRoot'),parentOf=get(Node.prototype,'parentElement'),hostOf=get(ShadowRoot.prototype,'host'),baseOf=get(Node.prototype,'baseURI'),doc=k=>get(Document.prototype,k).call(document);
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
  const CODE=/(^|[^a-z0-9])(otp|totp|mfa|2fa|tfa|one.?time|verification.?code|verify.?code|auth.?code|authenticator|sms.?code|security.?code)([^a-z0-9]|$)|(^| )code( |$)/;
  const USER=/user|login|log.?on|e.?mail|identifier|account|member|customer/,SEARCH=/search|(^| )q( |$)|query/;
  const CARD=/(^| )(card.?(number|num|no)|cc.?(number|num|exp)|cvv|cvc)( |$)/;
  const GO=/\b(sign.?in|log.?in|log.?on|next|continue|submit|verify|confirm|proceed)\b/;
  const AWAY=/\bwith\b|forgot|reset|sign.?up|register|create|join|passkey|security key|google|apple|facebook|microsoft|github|twitter|amazon|sso|single sign|another|different|cancel|back|help|show|hide|remember|qr|text me|email me|magic|one.?time/;
  const PAY=/\b(pay|payment|book|purchase|place (your |my )?order|buy|check.?out)\b/;
  const SIGNUP=/sign.?up|register|create.{0,12}account|subscribe|newsletter|forgot|reset|recover/;
  const isCode=el=>auto(el).includes('one-time-code')||CODE.test(named(el));
  const inputs=all('input').filter(shows);
  const passwords=inputs.filter(el=>type(el)==='password'&&!isCode(el));
  const editable=el=>!el.disabled&&!el.readOnly;
  const password=passwords.find(editable)||null;
  const codes=inputs.filter(el=>['text','tel','number','password'].includes(type(el))&&isCode(el)&&editable(el));
  const code=codes[0]||null;
  const hinted=el=>auto(el).includes('username')||auto(el).includes('email')||type(el)==='email'||USER.test(named(el));
  const texts=inputs.filter(el=>['text','email','tel'].includes(type(el))&&editable(el)&&!isCode(el)&&!SEARCH.test(named(el))&&type(el)!=='search'&&(!password||el.form===password.form));
  const before=password?texts.filter(el=>el.compareDocumentPosition(password)&Node.DOCUMENT_POSITION_FOLLOWING).pop():null;
  const username=texts.find(el=>auto(el).includes('username'))||texts.find(el=>auto(el).includes('email')||type(el)==='email')||texts.find(el=>USER.test(named(el)))||before||null;
  const primary=password||code||username;
  const form=primary?.form||null;
  const report={passwordCount:passwords.length,password:!!password,code:!!code,username:!!username,newPassword:passwords.some(el=>auto(el).includes('new-password')),
    cards:all('input,select').some(el=>auto(el).some(t=>t.startsWith('cc-')))||inputs.some(el=>CARD.test(named(el))),
    passkey:!primary&&/passkey|security key|use your (fingerprint|face)/i.test(doc('body')?.innerText||''),
    captchaPage:/just a moment|are you (a )?(human|robot)|captcha/i.test(doc('title'))};
  const label=el=>((tagOf.call(el)==='INPUT'?el.value||attr.call(el,'alt'):inner(el))||attr.call(el,'aria-label')||attr.call(el,'title')||'').trim().toLowerCase().slice(0,80);
  const typed=el=>tagOf.call(el)==='INPUT'?['submit','image'].includes(type(el)):tagOf.call(el)==='BUTTON'&&(!attr.call(el,'type')||type(el)==='submit');
  const clickable=el=>tagOf.call(el)==='INPUT'?['submit','image','button'].includes(type(el)):tagOf.call(el)==='BUTTON'?type(el)!=='reset':tagOf.call(el)==='A'?low(el,'role')==='button'||/^(#|javascript:)/.test(low(el,'href')):true;
  const inside=(box,el)=>{for(let n=el;n;n=hostAbove(n))if(contains.call(box,n))return true;return false;};
  const reads=el=>GO.test(label(el))&&!AWAY.test(label(el));
  let control=null,submitByForm=false;
  if(primary){
    const candidates=all('button,input,[role="button"],a').filter(el=>shows(el)&&clickable(el));
    let pool=form?candidates.filter(el=>formOf(el)===form||inside(form,el)):[];
    // No form, or a form that keeps its button outside it: the nearest box holding a sign-in control, leaving other forms' controls out.
    if(!form||!pool.some(el=>reads(el)||typed(el)))for(let box=primary,depth=0;box&&depth<24;depth++){
      box=parentOf.call(box)||hostAbove(box);if(!box)break;
      const near=candidates.filter(el=>inside(box,el)&&(!form||!formOf(el)||formOf(el)===form));
      if(!form)pool=near;
      if(near.some(reads)){pool=near;break;}
    }
    const away=el=>AWAY.test(label(el));
    const go=pool.filter(reads),submits=pool.filter(typed),goSubmits=go.filter(typed),plain=submits.filter(el=>!away(el));
    const one=list=>new Set(list.map(label)).size===1?list[0]:null;
    if(pool.some(el=>typed(el)&&PAY.test(label(el)))||go.some(el=>PAY.test(label(el))))report.refuse='pay-button';
    else if(goSubmits.length){control=one(goSubmits);if(!control)report.wall='no-clear-submit';}
    else if(form&&plain.length){control=plain.length===1?plain[0]:null;if(!control)report.wall='no-clear-submit';}
    else if(go.length){control=one(go);if(!control)report.wall='no-clear-submit';}
    else if(submits.length){if(submits.some(el=>SIGNUP.test(label(el))))report.refuse='sign-up';else report.wall='no-clear-submit';}
    else if(form){if(pool.some(el=>tagOf.call(el)!=='A'&&SIGNUP.test(label(el))))report.refuse='sign-up';else submitByForm=true;}
    else report.wall='no-clear-submit';
    // A username-only step has no password to say what it is, and an email box can be anything.
    if(!password&&!code&&!report.refuse){
      const says=[named(username),low(form,'id'),low(form,'name'),low(form,'action'),control?label(control):'',location.pathname.toLowerCase()].join(' ');
      if(SIGNUP.test(says)||!hinted(username)||(control?!GO.test(label(control)):!report.wall))report.refuse='not-sign-in-step';
    }
    if(codes.length>1&&!password)report.wall='code-boxes';
  }
  if(!password&&passwords.length)report.wall='field-not-editable';
  // By getAttribute, since form.action and form.method read an <input name=action> instead of the attribute.
  // phantab: an action it cannot resolve is not null (no action) but a mark the call refuses on.
  const action=()=>{const a=(control?attr.call(control,'formaction'):null)||(form?attr.call(form,'action'):null);if(!a||/^\s*javascript:/i.test(a))return null;try{return new URL(a,baseOf.call(form||document)).href;}catch{return {unresolved:true};}};
  report.href=location.href;report.ancestors=[...location.ancestorOrigins];report.action=action();
  const o={report,password,username,code,control,form,submitByForm,action,stoppedGet:false,filled:[]};
  o.state=()=>({connected:!!primary?.isConnected,shown:!!primary&&shows(primary),codeBeside:all('input').some(el=>shows(el)&&isCode(el)),passwordBeside:all('input').some(el=>shows(el)&&type(el)==='password'&&!isCode(el)),stoppedGet:o.stoppedGet});
  return o;
}