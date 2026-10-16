export class ArcopClient {
 constructor({baseUrl,token,tenant,fetchImpl=fetch}){const u=new URL(baseUrl);if(u.protocol!=='https:'||u.username||u.password)throw new Error('HTTPS endpoint without credentials required');this.baseUrl=u.href.replace(/\/$/,'');this.token=token;this.tenant=tenant;this.fetch=fetchImpl;}
 async request(path,{method='GET',body,idempotencyKey}={}){if(!/^\/requests(?:\/[a-f0-9-]+\/events|\/[a-f0-9-]+\/transitions)?$/.test(path))throw new Error('Unsupported resource');const r=await this.fetch(this.baseUrl+'/v1'+path,{method,redirect:'error',headers:{Authorization:'Bearer '+this.token,'X-Tenant-ID':this.tenant,...(body?{'Content-Type':'application/json'}:{}),...(idempotencyKey?{'Idempotency-Key':idempotencyKey}:{})},body:body?JSON.stringify(body):undefined});if(!r.ok)throw new Error('ARCOP request failed: '+r.status);return r.json();}
}
export function connectArcopFrame(iframe,{serviceOrigin,tenant,getToken}){
 const origin=new URL(serviceOrigin).origin;
 const listener=async e=>{if(e.source!==iframe.contentWindow||e.origin!==origin||e.data?.type!=='arcop.ready')return;iframe.contentWindow.postMessage({type:'arcop.session',tenant,token:await getToken()},origin);};
 window.addEventListener('message',listener);return()=>window.removeEventListener('message',listener);
}
