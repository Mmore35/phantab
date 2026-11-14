()=>{
  // phantab: through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <img name=querySelectorAll> shadows, nor a <form>'s, which its fields shadow.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,shadowOf=get(Element.prototype,'shadowRoot'),doc=k=>get(Document.prototype,k).call(document),inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined;
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s);
  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
  const text=[doc('title'),inner(doc('body'))||''];
  roots.forEach((root,i)=>{if(i)for(const child of root.children)if(inner(child))text.push(inner(child));});
  return {href:location.href,text:text.join('\n'),values:roots.flatMap(root=>[...qsa(root,'input')]).map(el=>el.value)};
}