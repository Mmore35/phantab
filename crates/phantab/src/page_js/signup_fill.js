(o,asked,value)=>{
  // phantab's own (browser_sign_up): one value into every new-password field, by the native setter and the events a person's typing sends. It never ticks a box or submits. Through the prototypes, never the form's own properties, which markup such as <input name=getAttribute> shadows.
  const attr=Element.prototype.getAttribute,listen=EventTarget.prototype.addEventListener,connected=Object.getOwnPropertyDescriptor(Node.prototype,'isConnected').get;
  const field=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value'),setter=field.set,getter=field.get;
  const typeOf=el=>(attr.call(el,'type')||'').toLowerCase();
  if(location.href!==asked.href||JSON.stringify([...location.ancestorOrigins])!==JSON.stringify(asked.ancestors)||JSON.stringify(o.actions())!==JSON.stringify(asked.actions))return 'moved';
  if(!o.fields.length||o.fields.some(el=>!connected.call(el)||el.disabled||el.readOnly||typeOf(el)!=='password'))return 'moved';
  const events=el=>{el.dispatchEvent(new Event('input',{bubbles:true,composed:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
  o.blank=()=>{for(const el of o.fields)if(getter.call(el)){setter.call(el,'');events(el);}};
  listen.call(window,'pagehide',o.blank,{once:true});
  // A show-password toggle turns a field into text: the field is blanked in the same task, before the page paints it (reblank on reveal).
  const watch=new MutationObserver(()=>{for(const el of o.fields)if(typeOf(el)!=='password'&&getter.call(el)){setter.call(el,'');events(el);}});
  for(const el of o.fields)watch.observe(el,{attributes:true,attributeFilter:['type']});
  for(const el of o.fields){
    setter.call(el,value);
    for(const n of ['keydown','keyup'])el.dispatchEvent(new KeyboardEvent(n,{bubbles:true,composed:true,cancelable:true}));
    events(el);
  }
  // On the form's root, since submit does not cross a shadow boundary: a GET submit would put the password in the address.
  if(o.form)listen.call(Node.prototype.getRootNode.call(o.form),'submit',e=>{
    if(e.target!==o.form||e.defaultPrevented||/^\s*javascript:/i.test(attr.call(o.form,'action')||''))return;
    if(((e.submitter?attr.call(e.submitter,'formmethod'):null)||attr.call(o.form,'method')||'get').toLowerCase()==='get'){e.preventDefault();o.stoppedGet=true;}
  });
  return o.fields.every(el=>getter.call(el)===value)?'filled':'not-taken';
}