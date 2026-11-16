(values)=>{
  const roots=[document];
  // phantab: through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <img name=querySelectorAll> shadows, nor a <form role=button>'s, which its fields shadow.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,shadowOf=get(Element.prototype,'shadowRoot'),tagOf=get(Element.prototype,'tagName'),idOf=get(Element.prototype,'id'),attr=Element.prototype.getAttribute,rects=Element.prototype.getClientRects,doc=k=>get(Document.prototype,k).call(document);
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s),inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined;
  for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
  // phantab: a text field's value, asked for only at parity (THREAT-MODEL R8): never a password's, nor a field the page marks as a password, card or code, nor any field of a form that holds a card, a code, a new password or two passwords, nor one named like a secret. Read through the prototypes, and cut at 200.
  const SECRET=/(^|\s)(cc-[\w-]*|one-time-code|new-password|current-password)(\s|$)/i,NAMED=/pass|pwd|secret|otp|cvv|cvc|ssn|card.?num/i,TEXTUAL=['text','search','email','url','tel','number','date','datetime-local','month','week','time'];
  const secretForm=f=>!!f&&(!!Element.prototype.querySelector.call(f,'input[autocomplete*="cc-"],input[autocomplete*="new-password"],input[autocomplete*="one-time-code"]')||Element.prototype.querySelectorAll.call(f,'input[type=password]').length>=2);
  const shown=el=>{const input=el instanceof HTMLInputElement,proto=input?HTMLInputElement.prototype:el instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:null;if(!proto||(input&&!TEXTUAL.includes(get(proto,'type').call(el))))return {};if(SECRET.test(attr.call(el,'autocomplete')||'')||NAMED.test((attr.call(el,'name')||'')+' '+(idOf.call(el)||''))||secretForm(get(proto,'form').call(el)))return {};const v=get(proto,'value').call(el);return v?{value:v.slice(0,200)}:{};};
  const text=[inner(doc('body'))||''],found=[];
  roots.forEach((root,i)=>{
    if(i)for(const child of root.children)if(rects.call(child).length&&!['STYLE','SCRIPT','LINK','SLOT'].includes(tagOf.call(child))&&inner(child))text.push(inner(child));
    for(const el of qsa(root,'a,button,input,select,textarea,[role="button"],[role="link"],[role="combobox"],[role="option"],[role="checkbox"],[role="radio"],[role="tab"],[role="menuitem"]')){
      const box=rects.call(el)[0];if(box)found.push({el,box,inShadow:i>0});
    }
  });
  const kept=found.length>180?[...found.filter(f=>tagOf.call(f.el)!=='A'),...found.filter(f=>tagOf.call(f.el)==='A')].slice(0,180):found;
  const elements=kept.map(({el,box,inShadow})=>{
    const x=Math.round(box.x+box.width/2),y=Math.round(box.y+box.height/2);
    const tag=tagOf.call(el);
    return {tag:tag.toLowerCase(),id:idOf.call(el)||undefined,name:attr.call(el,'name')||undefined,type:attr.call(el,'type')||undefined,text:((tag==='TEXTAREA'?'':inner(el))||attr.call(el,'aria-label')||attr.call(el,'placeholder')||'').slice(0,160),href:tag==='A'?el.href:undefined,...(el instanceof HTMLInputElement&&get(HTMLInputElement.prototype,'checked').call(el)?{checked:true}:{}),...(el instanceof HTMLSelectElement?{selected:Array.prototype.map.call(get(HTMLSelectElement.prototype,'selectedOptions').call(el),o=>get(HTMLOptionElement.prototype,'label').call(o)).join(', ')}:{}),...(values===true?shown(el):{}),x,y,...(inShadow?{inShadow:true}:{}),...(x<0||y<0||x>=innerWidth||y>=innerHeight?{offscreen:true}:{})};
  });
  return {title:doc('title'),text:text.join('\n').slice(0,18000),elements,omitted:found.length-kept.length,view:[innerWidth,innerHeight],shadowRoots:roots.length-1};
}