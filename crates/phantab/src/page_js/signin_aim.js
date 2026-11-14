o=>{
  // phantab: through the prototypes, never the control's own properties, which the fields of a <form role=button> (<input name=getAttribute>) shadow.
  const E=Element.prototype,N=Node.prototype,c=o.control;if((c instanceof HTMLFormElement?undefined:c.disabled)||E.getAttribute.call(c,'aria-disabled')==='true')return null;
  E.scrollIntoView.call(c,{block:'center',inline:'center',behavior:'instant'});
  const b=E.getBoundingClientRect.call(c),x=b.left+b.width/2,y=b.top+b.height/2,root=N.getRootNode.call(c),hit=(root instanceof ShadowRoot?ShadowRoot.prototype:Document.prototype).elementFromPoint.call(root,x,y);
  // phantab: not when a frame element is what the press would land on: an <iframe> inside the control, or in an open shadow root there.
  const get=k=>Object.getOwnPropertyDescriptor(Element.prototype,k).get;let deep=hit;for(let i=0,r;deep&&i<32&&(r=get('shadowRoot').call(deep));i++){const d=r.elementFromPoint(x,y);if(!d||d===deep)break;deep=d;}
  return hit&&(hit===c||N.contains.call(c,hit))&&!(deep!==c&&/^(iframe|frame|object|embed|fencedframe)$/.test(get('localName').call(deep)))?{x,y}:null;
}