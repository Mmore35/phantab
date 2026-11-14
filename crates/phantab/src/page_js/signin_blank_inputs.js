wanted=>{
  // phantab: through the prototypes, never the document's own properties, which markup such as <img name=querySelectorAll> shadows.
  const shadowOf=Object.getOwnPropertyDescriptor(Element.prototype,'shadowRoot').get,qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s);
  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  roots.flatMap(root=>[...qsa(root,'input')]).forEach((el,i)=>{
    if(wanted==='passwords'?!(el.type==='password'&&el.value):!wanted.includes(i))return;
    setter.call(el,'');el.dispatchEvent(new Event('input',{bubbles:true,composed:true}));el.dispatchEvent(new Event('change',{bubbles:true}));
  });
}