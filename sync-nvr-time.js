const http=require('http'),crypto=require('crypto');
const NVRS=[{name:'Depozit Caldararu',ip:'5.2.140.62',port:81,user:'admin',pass:'yoskoyos1987'}];
const DRIFT=120;
function pad(n){return String(n).padStart(2,'0');}
function getBuch(){
  const now=new Date();
  const l=new Date(now.toLocaleString('en-US',{timeZone:'Europe/Bucharest'}));
  const u=new Date(now.toLocaleString('en-US',{timeZone:'UTC'}));
  const oh=Math.round((l-u)/3600000);
  const os=(oh>=0?'+':'-')+pad(Math.abs(oh))+':00';
  const iso=l.getFullYear()+'-'+pad(l.getMonth()+1)+'-'+pad(l.getDate())+'T'+pad(l.getHours())+':'+pad(l.getMinutes())+':'+pad(l.getSeconds());
  return{iso,os,nowMs:now.getTime()};
}
function dig(method,path,body,nvr){
  return new Promise(function(resolve,reject){
    const agent=new http.Agent({keepAlive:true,maxSockets:1});
    const r1=http.request({host:nvr.ip,port:nvr.port,path:path,method:'GET',agent:agent,headers:{'Accept':'application/xml'}},function(s1){
      const wa=s1.headers['www-authenticate']||'';
      s1.resume();
      s1.on('end',function(){
        const get=function(k){const m=wa.match(new RegExp(k+'="([^"]*)"'));return m?m[1]:'';};
        const realm=get('realm'),nonce=get('nonce'),qop=get('qop'),opaque=get('opaque');
        const nc='00000001',cn=crypto.randomBytes(4).toString('hex');
        const md5=function(s){return crypto.createHash('md5').update(s).digest('hex');};
        const ha1=md5(nvr.user+':'+realm+':'+nvr.pass),ha2=md5(method+':'+path);
        const resp=qop?md5(ha1+':'+nonce+':'+nc+':'+cn+':'+qop+':'+ha2):md5(ha1+':'+nonce+':'+ha2);
        const ah='Digest username="'+nvr.user+'",realm="'+realm+'",nonce="'+nonce+'",uri="'+path+'"'+(qop?',qop='+qop+',nc='+nc+',cnonce="'+cn+'"':'')+',response="'+resp+'"'+(opaque?',opaque="'+opaque+'"':'');
        const bb=Buffer.from(body||'','utf8');
        const hdrs={'Authorization':ah,'Accept':'application/xml','Content-Length':bb.length};
        if(body)hdrs['Content-Type']='application/xml';
        const r2=http.request({host:nvr.ip,port:nvr.port,path:path,method:method,agent:agent,headers:hdrs},function(s2){
          let d='';s2.on('data',function(x){d+=x;});s2.on('end',function(){agent.destroy();resolve({status:s2.statusCode,body:d});});
        });
        r2.on('error',function(e){agent.destroy();reject(e);});
        if(body)r2.write(bb);
        r2.end();
      });
    });
    r1.on('error',function(e){agent.destroy();reject(e);});
    r1.setTimeout(8000,function(){agent.destroy();reject(new Error('timeout'));});
    r1.end();
  });
}
async function syncNvr(nvr){
  try{
    const r=await dig('GET','/ISAPI/System/status',null,nvr);
    if(r.status!==200){console.log('['+nvr.name+'] status '+r.status);return;}
    const tag='currentDeviceTime';
    const s=r.body.indexOf('<'+tag+'>'),e=r.body.indexOf('</'+tag+'>');
    if(s<0){console.log('['+nvr.name+'] nu gasesc currentDeviceTime');return;}
    const dt=r.body.slice(s+tag.length+2,e);
    const nvrTime=new Date(dt);
    const t=getBuch();
    const drift=Math.abs(t.nowMs-nvrTime.getTime())/1000;
    console.log('['+nvr.name+'] ora NVR: '+dt+' | deriva: '+Math.round(drift)+'s');
    if(drift<=DRIFT){console.log('['+nvr.name+'] ora OK');return;}
    const body='<?xml version="1.0" encoding="UTF-8"?><Time><timeMode>manual</timeMode><localTime>'+t.iso+t.os+'</localTime><timeZone>EET-2:00:00EEST01:00:00,M3.5.0/3,M10.5.0/4</timeZone></Time>';
    const r2=await dig('PUT','/ISAPI/System/time',body,nvr);
    console.log('['+nvr.name+'] sync '+(r2.status===200?'OK':'FAIL '+r2.status)+' -> '+t.iso+t.os);
  }catch(e){console.log('['+nvr.name+'] eroare: '+e.message);}
}
async function main(){
  console.log('=== Sync ora NVR '+new Date().toLocaleString('ro-RO',{timeZone:'Europe/Bucharest'})+' ===');
  for(const nvr of NVRS)await syncNvr(nvr);
  console.log('Done');
}
main();
