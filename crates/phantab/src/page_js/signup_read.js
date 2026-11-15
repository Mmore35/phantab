()=>{
  // phantab's own (the sign-up sweep): every input's and textarea's value and type, and the frame's text. Through the prototypes, as the sign-in sweep reads.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,shadowOf=get(Element.prototype,'shadowRoot'),doc=k=>get(Document.prototype,k).call(document),inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined,attr=Element.prototype.getAttribute;
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s);
  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
  const text=[doc('title'),inner(doc('body'))||''];
  roots.forEach((root,i)=>{if(i)for(const child of root.children)if(inner(child))text.push(inner(child));});
  const iv=get(HTMLInputElement.prototype,'value'),tv=get(HTMLTextAreaElement.prototype,'value');
  const els=roots.flatMap(root=>[...qsa(root,'input,textarea')]);
  return {href:location.href,text:text.join('\n'),values:els.map(el=>el instanceof HTMLTextAreaElement?tv.call(el):iv.call(el)),types:els.map(el=>el instanceof HTMLTextAreaElement?'textarea':(attr.call(el,'type')||'text').toLowerCase())};
}