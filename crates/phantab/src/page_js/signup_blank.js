wanted=>{
  // phantab's own (the sign-up sweep): blanks the inputs and textareas at these indices of signup_read.js's list.
  const shadowOf=Object.getOwnPropertyDescriptor(Element.prototype,'shadowRoot').get,qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s);
  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
  const is=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set,ts=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
  roots.flatMap(root=>[...qsa(root,'input,textarea')]).forEach((el,i)=>{
    if(!wanted.includes(i))return;
    (el instanceof HTMLTextAreaElement?ts:is).call(el,'');el.dispatchEvent(new Event('input',{bubbles:true,composed:true}));el.dispatchEvent(new Event('change',{bubbles:true}));
  });
}