"use strict";
const $=s=>document.querySelector(s),enc=new TextEncoder,dec=new TextDecoder;
const CH=64*1024,HI=4*1024*1024,LO=1024*1024,PFX="hashdrop-";
const b64=u=>btoa(String.fromCharCode(...u)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
const size=n=>n<1e3?Math.round(n)+" B":n<1e6?(n/1e3).toFixed(0)+" KB":n<1e9?(n/1e6).toFixed(1)+" MB":(n/1e9).toFixed(2)+" GB";
const show=(id,on=true)=>{$(id).hidden=!on};
const say=(t,err)=>{const s=$("#st");s.textContent=t;s.className="status"+(err?" err":"")};
const fmt=c=>c.slice(0,3)+" "+c.slice(3);

/* keep working while the tab is hidden */
let busy=false,wl=null,rel=null,peer=null,t0=0;
async function hold(){
  try{wl=await navigator.wakeLock?.request("screen")}catch{}
  if(!rel&&navigator.locks)navigator.locks.request("passage",()=>new Promise(r=>{rel=r}));
}
function letgo(){busy=false;try{wl?.release()}catch{}wl=null;rel?.();rel=null}
document.addEventListener("visibilitychange",()=>{if(busy&&document.visibilityState==="visible")hold()});
addEventListener("beforeunload",e=>{if(busy){e.preventDefault();e.returnValue=""}});

/* crypto: ECDH P-256 -> HKDF(salt = link secret + passphrase key) -> AES-256-GCM */
async function pwKey(p){
  const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc.encode("passage-v1"),iterations:200000},k,256));
}
async function derive(mine,theirRaw,salt){
  const pub=await crypto.subtle.importKey("raw",theirRaw,{name:"ECDH",namedCurve:"P-256"},false,[]);
  const bits=await crypto.subtle.deriveBits({name:"ECDH",public:pub},mine.privateKey,256);
  const hk=await crypto.subtle.importKey("raw",bits,"HKDF",false,["deriveKey","deriveBits"]);
  const p=i=>({name:"HKDF",hash:"SHA-256",salt,info:enc.encode(i)});
  const key=await crypto.subtle.deriveKey(p("key"),hk,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  const s=new Uint8Array(await crypto.subtle.deriveBits(p("sas"),hk,24));
  return{key,sas:fmt(String(((s[0]<<16|s[1]<<8|s[2])>>>0)%1e6).padStart(6,"0"))};
}
const hdr=(t,n)=>{const h=new Uint8Array(5);h[0]=t;new DataView(h.buffer).setUint32(1,n);return h};
const iv=n=>{const v=new Uint8Array(12);new DataView(v.buffer).setUint32(8,n);return v};
async function seal(st,type,data){
  const n=st.tx++,h=hdr(type,n);
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv(n),additionalData:h},st.key,data));
  const o=new Uint8Array(5+ct.length);o.set(h);o.set(ct,5);return o.buffer;
}
async function unseal(st,buf){
  const u=new Uint8Array(buf),h=u.slice(0,5),n=new DataView(h.buffer).getUint32(1);
  if(n!==st.rx++)throw new Error("Frame out of order");
  return{type:h[0],data:await crypto.subtle.decrypt({name:"AES-GCM",iv:iv(n),additionalData:h},st.key,u.subarray(5))};
}
function mailbox(){
  const box={},wait={};
  return{push(m){wait[m.t]?(wait[m.t](m),delete wait[m.t]):box[m.t]=m},
    next(t){return new Promise(r=>{if(box[t]){r(box[t]);delete box[t]}else wait[t]=r})}};
}
async function handshake(conn,mb,secret,isSender,pass,secure){
  const dc=conn.dataChannel;dc.bufferedAmountLowThreshold=LO;
  const kp=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
  const raw=new Uint8Array(await crypto.subtle.exportKey("raw",kp.publicKey));
  dc.send(JSON.stringify({t:"k",k:b64(raw),s:secret?1:0,p:isSender&&pass?1:0,m:isSender&&secure?1:0}));
  const them=await mb.next("k");
  if(!isSender&&them.p){
    show("#pw");say("");
    pass=await new Promise(r=>{$("#pwy").onclick=()=>r($("#pwr").value)});
    show("#pw",false);say("Securing the channel…");
  }
  const useSecret=isSender?them.s===1:!!secret;
  const sec=useSecret&&secret?secret:new Uint8Array(0),pk=pass?await pwKey(pass):new Uint8Array(0);
  const {key,sas}=await derive(kp,unb(them.k),new Uint8Array([...sec,...pk]));
  const need=isSender?secure:them.m===1;
  if(need){
    $("#sas").textContent=sas;show("#vf");say("Compare this code with the other device.");
    const ok=await new Promise(r=>{$("#vy").onclick=()=>r(1);$("#vn").onclick=()=>r(0)});
    show("#vf",false);
    if(!ok){dc.send(JSON.stringify({t:"no"}));throw new Error("Verification failed. Transfer cancelled.")}
  }
  dc.send(JSON.stringify({t:"ok"}));await mb.next("ok");
  return{dc,st:{key,tx:0,rx:0}};
}
function prog(name,done,total,label){
  show("#pg");$("#pn").textContent=(label?label+" · ":"")+name;
  const f=total?done/total:1;$("#pb").style.width=(f*100).toFixed(1)+"%";$("#pp").textContent=Math.floor(f*100)+"%";
  const dt=(performance.now()-t0)/1000;$("#ps").textContent=dt>.5?size(done/dt)+"/s":"";
}
const live=()=>{show("#pSend",false);show("#pRecv",false);show("#pLive")};
function fail(e){letgo();say(e.message||String(e),true);show("#again");try{peer?.destroy()}catch{}}
$("#ag").onclick=()=>{location.href=location.pathname};

/* ---------- SEND ---------- */
const S={secure:false,files:[],i:0,off:0,run:0,conn:null,started:false,done:false,pass:""};
function pick(list){S.files=[...list];if(S.files.length)startSend()}
$("#bf").onclick=()=>$("#fi").click();$("#bd").onclick=()=>$("#di").click();
$("#fi").onchange=e=>pick(e.target.files);$("#di").onchange=e=>pick(e.target.files);
const dz=$("#dz");
["dragover","dragenter"].forEach(v=>dz.addEventListener(v,e=>{e.preventDefault();dz.classList.add("on")}));
["dragleave","drop"].forEach(v=>dz.addEventListener(v,e=>{e.preventDefault();dz.classList.remove("on")}));
dz.addEventListener("drop",e=>pick(e.dataTransfer.files));

function startSend(){
  S.pass=$("#pwi").value;S.secure=$("#sec").checked;show("#s0",false);show("#s1");
  for(const f of S.files){const li=document.createElement("li"),a=document.createElement("span"),b=document.createElement("span");a.textContent=f.webkitRelativePath||f.name;b.textContent=size(f.size);li.append(a,b);$("#fl").append(li)}
  const secret=rnd(16);
  const go=()=>{
    const code=String(new DataView(rnd(4).buffer).getUint32(0)%1e6).padStart(6,"0");
    peer=new Peer(PFX+code,{debug:0});
    peer.on("error",e=>e.type==="unavailable-id"?go():fail(new Error("Could not reach the pairing service.")));
    peer.on("open",()=>{
      const link=location.href.split("#")[0].split("?")[0]+"#"+code+"."+b64(secret);
      $("#otp").textContent=fmt(code);
      const q=qrcode(0,"M");q.addData(link);q.make();$("#qr").src=q.createDataURL(5,0);
      $("#cp").onclick=async()=>{try{await navigator.clipboard.writeText(link);$("#cp").textContent="Copied"}catch{prompt("Copy link",link)}setTimeout(()=>$("#cp").textContent="Copy link",1500)};
      $("#cx").onclick=()=>location.reload();
    });
    peer.on("connection",conn=>{
      if(S.conn?.open){conn.close();return}
      S.conn=conn;const run=++S.run,mb=mailbox();let ran=false;
      conn.on("data",d=>{if(typeof d!=="string")return;const m=JSON.parse(d);m.t==="no"?fail(new Error("The receiver rejected the verification code.")):mb.push(m)});
      conn.on("close",()=>{if(!S.done&&S.started&&run===S.run){say("Connection lost. Waiting for the receiver to reconnect…",true);show("#pg",false)}});
      conn.on("open",async()=>{
        if(ran)return;ran=true;
        try{
          busy=true;hold();live();say(S.started?"Receiver is back. Re-securing…":"Connected. Securing the channel…");
          const{dc,st}=await handshake(conn,mb,secret,true,S.pass,S.secure);
          S.started=true;await sendAll(dc,st,mb,run);
        }catch(e){if(e.message!=="stale")fail(e)}
      });
    });
  };
  go();
}
async function sendAll(dc,st,mb,run){
  const alive=()=>{if(run!==S.run||!S.conn?.open)throw new Error("stale")};
  const put=async b=>{if(dc.bufferedAmount>HI)await new Promise(r=>dc.addEventListener("bufferedamountlow",r,{once:true}));alive();dc.send(b)};
  for(;S.i<S.files.length;S.i++){
    const f=S.files[S.i],name=f.webkitRelativePath||f.name,lab=`${S.i+1}/${S.files.length}`;
    say(`Waiting for the receiver to accept ${name}…`);
    dc.send(await seal(st,0,enc.encode(JSON.stringify({name,size:f.size,mime:f.type,i:S.i,n:S.files.length}))));
    const g=await mb.next("go");alive();
    if(g.no){S.off=0;continue}
    S.off=g.off||0;say("Sending…");t0=performance.now()-(S.off?500:0);
    for(let o=S.off;o<f.size;o+=CH){
      alive();const buf=await f.slice(o,o+CH).arrayBuffer(),p=new Uint8Array(8+buf.byteLength);
      new DataView(p.buffer).setFloat64(0,o);p.set(new Uint8Array(buf),8);
      await put(await seal(st,1,p));S.off=Math.min(o+CH,f.size);prog(name,S.off,f.size,lab);
    }
    await put(await seal(st,2,new Uint8Array(0)));await mb.next("done");alive();S.off=0;
  }
  S.done=true;prog("All files delivered",1,1);$("#pg").classList.add("done");$("#ps").textContent="";say("Done. Nothing was stored anywhere.");
  show("#again");letgo();setTimeout(()=>peer?.destroy(),1500);
}

/* ---------- RECEIVE ---------- */
const R={cur:null,fin:new Set(),dir:null,auto:false,tries:0,all:false,q:Promise.resolve()};
const safe=s=>s.split("/").filter(x=>x&&x!=="."&&x!=="..").map(x=>x.replace(/[\\:*?"<>|]/g,"_"));
async function openWriter(c){
  if(R.dir){const p=safe(c.name),n=p.pop();let d=R.dir;for(const s of p)d=await d.getDirectoryHandle(s,{create:true});c.w=await(await d.getFileHandle(n,{create:true})).createWritable()}
}
function connectRecv(code,secret){
  live();say("Connecting…");busy=true;hold();
  peer=new Peer({debug:0});
  peer.on("error",e=>fail(new Error(e.type==="peer-unavailable"?"No sender found for that code. It may have expired.":"Could not reach the pairing service.")));
  peer.on("open",()=>{
    const conn=peer.connect(PFX+code,{serialization:"raw",reliable:true});
    const mb=mailbox();let st=null,dc=null;
    conn.on("error",()=>{});
    conn.on("close",()=>{
      if(!busy||R.all)return;
      if(R.tries++<8){say("Connection lost. Reconnecting…",true);show("#pg",false);setTimeout(()=>{try{peer.destroy()}catch{}connectRecv(code,secret)},1500)}
      else fail(new Error("Could not reconnect to the sender."));
    });
    conn.on("data",d=>{
      if(typeof d==="string"){const m=JSON.parse(d);m.t==="no"?fail(new Error("The sender rejected the verification code.")):mb.push(m);return}
      R.q=R.q.then(()=>frame(d)).catch(e=>fail(e.name==="OperationError"?new Error("Decryption failed: wrong passphrase or tampered data."):e));
    });
    conn.on("open",async()=>{
      try{const r=await handshake(conn,mb,secret,false,null,false);dc=r.dc;st=r.st;R.tries=0;say(R.cur?"Reconnected. Resuming…":"Secure. Waiting for the sender…")}catch(e){fail(e)}
    });
    async function frame(buf){
      const{type,data}=await unseal(st,buf),c=R.cur;
      if(type===0){
        const m=JSON.parse(dec.decode(data));
        const reply=o=>{show("#ac",false);dc.send(JSON.stringify({t:"go",...o}))};
        if(R.fin.has(m.i))return reply({no:1});
        if(c&&c.i===m.i&&!c.finished){say("Resuming…");t0=performance.now();return reply({off:c.got})}
        const n=R.cur={i:m.i,n:m.n,name:safe(m.name).join("/")||"file",size:m.size,mime:m.mime||"",got:0,parts:[],w:null};
        if(R.auto){await openWriter(n);t0=performance.now();say("Receiving…");return reply({})}
        $("#ah").textContent=m.n>1?`Incoming: ${m.n} files`:"Incoming file";
        $("#an").textContent=`${n.name} (${size(n.size)})`;show("#ac");show("#pg",false);say("");
        $("#ax").onclick=()=>reply({no:1});
        $("#ay").onclick=async()=>{
          try{
            if(m.n>1&&window.showDirectoryPicker){R.dir=await showDirectoryPicker({mode:"readwrite"})}
            else if(m.n===1&&window.showSaveFilePicker){const nm=n.name.split("/").pop(),x=(nm.match(/\.[A-Za-z0-9]{1,10}$/)||[])[0];
              n.w=await(await showSaveFilePicker({suggestedName:nm,...(x?{types:[{description:x.slice(1).toUpperCase()+" file",accept:{[n.mime||"application/octet-stream"]:[x]}}]}:{})})).createWritable()}
            R.auto=m.n>1;await openWriter(n);
          }catch(e){if(e.name==="AbortError")return;return fail(e)}
          t0=performance.now();say("Receiving…");reply({});
        };
      }else if(type===1){
        const off=new DataView(data).getFloat64(0),len=data.byteLength-8;
        if(off>c.got)throw new Error("Data gap detected. Please retry.");
        if(off+len<=c.got)return;
        const part=data.slice(8+(c.got-off));
        if(c.w)await c.w.write({type:"write",position:c.got,data:part});else c.parts.push(part);
        c.got+=part.byteLength;prog(c.name,c.got,c.size,c.n>1?`${c.i+1}/${c.n}`:"");
      }else if(type===2){
        if(c.got!==c.size)throw new Error("File size mismatch.");
        if(c.w)await c.w.close();
        else{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob(c.parts,{type:c.mime}));a.download=c.name.replace(/\//g,"_");a.click();setTimeout(()=>URL.revokeObjectURL(a.href),6e4)}
        c.finished=true;c.parts=[];R.fin.add(c.i);try{dc.send(JSON.stringify({t:"done"}))}catch{}
        if(R.fin.size>=c.n){R.all=true;$("#pg").classList.add("done");say(c.n>1?"All files received.":"File received and saved.");show("#again");letgo()}
      }
    }
  });
}
$("#rg").onclick=()=>{const c=$("#rc").value.replace(/\D/g,"");c.length===6?connectRecv(c,null):$("#rc").focus()};
$("#rc").addEventListener("keydown",e=>{if(e.key==="Enter")$("#rg").click()});

$("#sec").onchange=e=>{const c=e.target.checked;
  $("#mn").textContent=c?"Most secure":"Quick";
  $("#mh").textContent=c?"Both people confirm a short code before anything is sent.":"Fastest. Connects right away, no code to compare."};
/* ---------- theme, text/paste, feedback ---------- */
const FEEDBACK_EMAIL="you@example.com"; /* change to your own address */
const root=document.documentElement;
try{const t=localStorage.getItem("hd-theme");if(t)root.dataset.theme=t}catch{}
$("#th").onclick=()=>{
  const dark=root.dataset.theme?root.dataset.theme==="dark":matchMedia("(prefers-color-scheme:dark)").matches,n=dark?"light":"dark";
  root.dataset.theme=n;try{localStorage.setItem("hd-theme",n)}catch{}
};
const idle=()=>!$("#pSend").hidden&&!$("#s0").hidden;
function sendText(t){
  t=t.trim();if(!t||!idle())return;
  pick([new File([t],"text-"+new Date().toISOString().slice(0,16).replace(/[:T]/g,"-")+".txt",{type:"text/plain"})]);
}
$("#tb").onclick=()=>{show("#tx",$("#tx").hidden);$("#ta").focus()};
$("#ts").onclick=()=>sendText($("#ta").value);
document.addEventListener("paste",e=>{
  if(!idle()||/^(INPUT|TEXTAREA)$/.test(e.target.tagName))return;
  const fs=e.clipboardData.files;
  if(fs.length){e.preventDefault();pick(fs);return}
  const t=e.clipboardData.getData("text");if(t){e.preventDefault();sendText(t)}
});
const dlg=$("#fbd");
$("#fbb").onclick=()=>dlg.showModal();$("#fx").onclick=()=>dlg.close();
$("#fy").onclick=()=>{
  const n=$("#fn").value.trim(),s=$("#fs").value.trim();if(!s){$("#fs").focus();return}
  location.href="mailto:"+FEEDBACK_EMAIL+"?subject="+encodeURIComponent("Hashdrop feedback"+(n?" from "+n:""))+"&body="+encodeURIComponent("Name: "+(n||"(not given)")+"\n\n"+s);
  dlg.close();
};
/* ---------- navigation ---------- */
function tab(r){
  $("#tS").setAttribute("aria-selected",!r);$("#tR").setAttribute("aria-selected",r);
  show("#pSend",!r);show("#pRecv",r);if(r)$("#rc").focus();
}
$("#tS").onclick=()=>tab(false);$("#tR").onclick=()=>tab(true);
const hm=location.hash.match(/^#(\d{6})\.([\w-]+)$/);
if(hm){history.replaceState(null,"",location.pathname);document.querySelector(".tabs").hidden=true;connectRecv(hm[1],unb(hm[2]))}
