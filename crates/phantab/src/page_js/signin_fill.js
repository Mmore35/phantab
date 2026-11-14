(o,asked,values)=>{
  // phantab: through the prototypes, never the form's own properties, which markup such as <input name=getAttribute> shadows.
  const attr=Element.prototype.getAttribute,listen=EventTarget.prototype.addEventListener;
  if(location.href!==asked.href||JSON.stringify([...location.ancestorOrigins])!==JSON.stringify(asked.ancestors)||(o.action()||null)!==(asked.action||null))return 'moved';
  for(const name of Object.keys(values))if(!o[name]?.isConnected)return 'moved';
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  const events=el=>{el.dispatchEvent(new Event('input',{bubbles:true,composed:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
  o.blank=()=>{for(const el of o.filled)if(el.value){setter.call(el,'');events(el);}};
  listen.call(window,'pagehide',o.blank,{once:true});
  for(const name of Object.keys(values)){
    const el=o[name];setter.call(el,values[name]);o.filled.push(el);
    for(const n of ['keydown','keyup'])el.dispatchEvent(new KeyboardEvent(n,{bubbles:true,composed:true,cancelable:true}));
    events(el);
  }
  // On the form's root, since submit doesn't cross a shadow boundary. Runs after the site's own listeners on
  // the form, so a form the site's scripts took over is left alone.
  if(o.form&&values.password!==undefined)listen.call(Node.prototype.getRootNode.call(o.form),'submit',e=>{
    if(e.target!==o.form||e.defaultPrevented||/^\s*javascript:/i.test(attr.call(o.form,'action')||''))return;
    if(((e.submitter?attr.call(e.submitter,'formmethod'):null)||attr.call(o.form,'method')||'get').toLowerCase()==='get'){e.preventDefault();o.stoppedGet=true;}
  });
  return values.password!==undefined&&o.password.value!==values.password?'not-taken':'filled';
}