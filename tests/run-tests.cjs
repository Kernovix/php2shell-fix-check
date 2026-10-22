/* Local fixtures only. Node.js + OpenSSL are test dependencies, not audit dependencies. */
'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const http=require('node:http'),https=require('node:https'),net=require('node:net'),assert=require('node:assert/strict');
const {spawn,spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),scratch=fs.mkdtempSync(path.join(os.tmpdir(),'php-audit-tests-'));
const snapshots={};
for(const name of ['PHP-Audit.ps1','php_audit.sh']){snapshots[name]=path.join(scratch,name).replace(/\\/g,'/');fs.copyFileSync(path.join(root,name),snapshots[name]);}
const win=process.platform==='win32',pf=process.env.ProgramFiles||'C:/Program Files';
let assertions=0;const check=(v,m)=>{assert.ok(v,m);assertions++};
function command(exe,args,timeout=240000){return new Promise((resolve,reject)=>{
  const child=spawn(exe,args,{cwd:root,windowsHide:true,env:{...process.env,MSYS_NO_PATHCONV:'1'}});let output='';
  const timer=setTimeout(()=>{child.kill();reject(Error('Test process deadline exceeded: '+exe));},timeout);
  child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);
  child.on('error',e=>{clearTimeout(timer);reject(e)});
  child.on('close',code=>{clearTimeout(timer);code===0?resolve(output):reject(Error(exe+' exit='+code+'\n'+output))});
})}
function csv(text){
  text=text.replace(/^\ufeff/,'');const rows=[];let row=[],cell='',quoted=false;
  for(let i=0;i<text.length;i++){const c=text[i];if(c==='"'){if(quoted&&text[i+1]==='"'){cell+='"';i++}else quoted=!quoted}
    else if(c===','&&!quoted){row.push(cell);cell=''}else if(c==='\n'&&!quoted){row.push(cell.replace(/\r$/,''));rows.push(row);row=[];cell=''}else cell+=c;}
  const head=rows.shift();return rows.filter(r=>r.length===head.length).map(r=>Object.fromEntries(head.map((h,i)=>[h,r[i]])));
}
const listen=server=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>resolve(server.address().port))});
const servers=[],sni=[],requests=[];
function handler(req,res){
  res.setHeader('Server','nginx/1.26.2');
  const name=req.headers.host.split(':')[0];requests.push(name);
  if(name==='slow.test'){return;}
  if(name==='redirect.test'){res.writeHead(302,{Location:'https://user:DO_NOT_LEAK@offscope.invalid/login?token=DO_NOT_LEAK#fragment'});return res.end();}
  if(name==='hint.test'){res.setHeader('X-Powered-By','PHP');res.setHeader('Set-Cookie','PHPSESSID=COOKIE_VALUE_DO_NOT_LEAK; HttpOnly');return res.end('Application');}
  if(name==='old.test'||name==='chunked.test'||name==='big.test'){res.setHeader('X-Powered-By','PHP/8.3.35');}
  if(name==='fixed.test'){res.setHeader('X-Powered-By','PHP/8.3.36');}
  if(name==='chunked.test'){res.write('<link href="/wp-co');res.write('ntent/theme.css">');return res.end();}
  if(name==='big.test'){return res.end('x'.repeat(120000));}
  res.end('<html><title>Static service</title><p>Documentation about PHP.</p></html>');
}
const available=exe=>spawnSync(exe,['--version'],{windowsHide:true}).status===0;
const bash=process.env.AUDIT_BASH||(win?path.join(pf,'Git/bin/bash.exe'):'/bin/bash');
const engines=[];
const required=(process.env.AUDIT_TEST_ENGINES||'').split(',').filter(Boolean);
for(const [id,exe]of [['bash',bash],['pwsh',process.env.AUDIT_PWSH||'pwsh'],...(win?[['ps51',path.join(process.env.SystemRoot||'C:/Windows','System32/WindowsPowerShell/v1.0/powershell.exe')]]:[])]){
  const exists=id==='ps51'?fs.existsSync(exe):available(exe);
  if(exists&&(!required.length||required.includes(id)))engines.push({id,exe});
}
for(const id of required)assert.ok(engines.some(e=>e.id===id),'Required engine unavailable: '+id);
assert.ok(engines.length,'No supported test engine found');
function audit(engine,targets,ports,extra=[],language='en'){
  const out=path.join(scratch,engine.id+'-'+Math.random().toString(16).slice(2));
  const args=engine.id==='bash'?[snapshots['php_audit.sh'],targets,language,'--ports',ports.join(','),'--tls-ports',String(tlsPort),'--timeout','1','--out',out,...extra]:['-NoProfile','-File',snapshots['PHP-Audit.ps1'],targets,language,'-Ports',ports.join(','),'-TlsPorts',String(tlsPort),'-TimeoutSeconds','1','-OutDir',out,...extra];
  // PowerShell -File does not bind a comma string to int[]; use a single port per call.
  assert.equal(ports.length,1);
  return command(engine.exe,args).then(output=>{
    if(/fork:|Resource temporarily unavailable|Too many open files|command not found|No such file or directory/.test(output))console.error(output);
    const dir=fs.readdirSync(out).find(n=>fs.statSync(path.join(out,n)).isDirectory());assert.ok(dir,'No report output');
    const csvText=fs.readFileSync(path.join(out,dir,'report.csv'),'utf8'),html=fs.readFileSync(path.join(out,dir,'report.html'),'utf8');
    check(!csvText.includes("\"'-\""),'unknown CSV markers are blank');check(!/COOKIE_VALUE_DO_NOT_LEAK|DO_NOT_LEAK/.test(csvText+html),'no cookie/query secrets in reports');
    return {rows:csv(csvText),html,csvText};
  });
}
let tlsPort;
async function simulated(engine,observations,evidence=[]){
  const out=path.join(scratch,'sim-'+engine.id+'-'+Math.random().toString(16).slice(2));
  fs.mkdirSync(out);const input=path.join(out,'input.tsv'),proof=path.join(out,'proof.tsv');
  const fields=['IP','Hostname','OS','Service','Runtime','Application','PHPVersion','Package','Reachable','Evidence'];
  if(observations[0].length===18)fields.push('Address','DiscoveryCode','HTTPStatus','TLSValidation','ErrorCode','ErrorDetail','RedirectTo','Confidence');
  fs.writeFileSync(input,[fields,...observations].map(r=>r.join('\t')).join('\n')+'\n');
  const args=engine.id==='bash'?[snapshots['php_audit.sh'],'en','--simulate',input,'--out',out]:['-NoProfile','-File',snapshots['PHP-Audit.ps1'],'-Language','en','-Simulate',input,'-OutDir',out];
  if(evidence.length){
    fs.writeFileSync(proof,[['IP','Service','Runtime','PHPVersion','Package','CVE109618','CVE109619','RuntimeVerified','ReviewedAt','ReviewedBy','Advisory'],...evidence].map(r=>r.join('\t')).join('\n')+'\n');
    args.push(engine.id==='bash'?'--evidence':'-EvidenceFile',proof);
  }
  await command(engine.exe,args);
  const dir=fs.readdirSync(out).find(n=>fs.statSync(path.join(out,n)).isDirectory());
  const text=fs.readFileSync(path.join(out,dir,'report.csv'),'utf8'),html=fs.readFileSync(path.join(out,dir,'report.html'),'utf8');
  return {rows:csv(text),text,html};
}
(async()=>{
  try{
    const openssl=process.env.OPENSSL||(win?path.join(pf,'Git/usr/bin/openssl.exe'):'openssl');
    const key=path.join(scratch,'fixture.key'),cert=path.join(scratch,'fixture.crt');
    await command(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-keyout',key,'-out',cert,'-subj','/CN=old.test','-addext','subjectAltName=DNS:old.test,DNS:localhost']);
    const plain=http.createServer(handler);servers.push(plain);const httpPort=await listen(plain);
    const secure=https.createServer({key:fs.readFileSync(key),cert:fs.readFileSync(cert),SNICallback:(name,cb)=>{sni.push(name);cb(null,require('node:tls').createSecureContext({key:fs.readFileSync(key),cert:fs.readFileSync(cert)}));}},handler);servers.push(secure);tlsPort=await listen(secure);
    const raw=net.createServer(socket=>{socket.on('error',()=>{});socket.end('NOT HTTP\r\n\r\n')});servers.push(raw);const rawPort=await listen(raw);
    const unused=net.createServer();const closedPort=await listen(unused);await new Promise(r=>unused.close(r));
    for(const engine of engines){
      const before=assertions;
      process.stdout.write('RUN '+engine.id+'\n');
      if(engine.id!=='bash'){
        const core=await command(engine.exe,['-NoProfile','-File','tests/Test-Core.ps1','-ScriptPath',snapshots['PHP-Audit.ps1']]);check(core.includes('CORE PASS'),'PowerShell native scope/WinRM/core assertions');process.stdout.write(engine.id+': '+core.trim()+'\n');
      }
      const selfOut=path.join(scratch,'self-'+engine.id);
      const selfArgs=engine.id==='bash'?[snapshots['php_audit.sh'],'--self-test','en','--out',selfOut]:['-NoProfile','-File',snapshots['PHP-Audit.ps1'],'-SelfTest','-Language','en','-WinRMPort','0','-OutDir',selfOut];
      const self=await command(engine.exe,selfArgs);check(self.includes('14')&&self.includes('7'),'21 built-in version/classification assertions');
      const selfDir=fs.readdirSync(selfOut)[0],sim=csv(fs.readFileSync(path.join(selfOut,selfDir,'report.csv'),'utf8'));
      check(sim.find(r=>r.VulnerabilityCode==='FIXED')?.PHP==='8.3.6','reviewed vendor backport accepted');
      check(sim.some(r=>r.VulnerabilityCode==='VULNERABLE_CONFIRMED'),'reviewed affected runtime confirmed');
      check(sim.find(r=>r.PHP==='8.5.12'&&r.Service==='CLI')?.VulnerabilityCode==='INCONCLUSIVE','CLI never proves fixed');
      const batch=await audit(engine,'plain.test=127.0.0.1,old.test=127.0.0.1,fixed.test=127.0.0.1,hint.test=127.0.0.1,redirect.test=127.0.0.1,chunked.test=127.0.0.1,big.test=127.0.0.1',[httpPort]);
      const find=name=>batch.rows.find(r=>r.Target===name+'.test=127.0.0.1');
      if(find('plain')?.DiscoveryCode!=='PHP_NOT_IDENTIFIED')console.error(batch.rows.map(r=>({target:r.Target,discovery:r.DiscoveryCode,error:r['Error code'],detail:r['Technical error']})));
      check(find('plain')?.DiscoveryCode==='PHP_NOT_IDENTIFIED','HTTP without PHP distinguished');
      check(find('plain')?.VulnerabilityCode==='INCONCLUSIVE','no PHP does not imply safety');
      check(find('plain')?.Evidence?.includes('ServerProduct=nginx/1.26.2'),'web-server product retained without raw header disclosure');
      check(find('old')?.VulnerabilityCode==='POTENTIALLY_VULNERABLE','old banner conservative');
      check(find('fixed')?.VulnerabilityCode==='INCONCLUSIVE','patched banner not certified');
      check(find('hint')?.DiscoveryCode==='PHP_NO_VERSION','PHP session/header without version');
      check(find('chunked')?.Application?.includes('WordPress'),'chunked body decoded');
      check(batch.html.includes('WordPress (hint)'),'application hints visible in HTML details');
      check(find('big')?.PHP==='8.3.35','large body preserves version headers');
      check(find('redirect')?.HTTP==='302','redirect response counted');
      check(Object.values(find('redirect')).includes('https://offscope.invalid/login'),'redirect retained without query/fragment');
      check(!requests.includes('offscope.invalid'),'redirect destination never followed');
      check(batch.rows.every(r=>r.CVEs?.includes('CVE-2026-109618')&&r.CVEs?.includes('CVE-2026-109619')),'both CVE identifiers exported');
      process.stdout.write(engine.id+': HTTP, PHP hints, chunked/capped bodies and redirects passed\n');
      const badTls=await audit(engine,'old.test=127.0.0.1',[tlsPort]);
      check(badTls.rows[0]?.['Error code']==='TLS_CERTIFICATE_INVALID','self-signed certificate rejected');
      check(badTls.rows[0]?.DiscoveryCode==='CONNECTION_ERROR','TLS error separate from vulnerability');
      check(badTls.rows[0]?.['Technical error']?.length>5,'sanitized technical TLS error preserved');
      const relaxed=await audit(engine,'old.test=127.0.0.1',[tlsPort],engine.id==='bash'?['--insecure-tls']:['-InsecureTls']);
      check(relaxed.rows[0]?.HTTP==='200','explicit diagnostic TLS opt-in works');
      check(relaxed.rows[0]?.['TLS validation']==='DISABLED','disabled validation visibly labelled');
      check(relaxed.rows[0]?.['Confidence in PHP evidence']==='LOW','unvalidated TLS low confidence');
      check(sni.includes('old.test'),'correct SNI reached TLS fixture');
      process.stdout.write(engine.id+': TLS validation and SNI passed\n');
      const refused=await audit(engine,'127.0.0.1',[closedPort]);
      if(refused.rows[0]?.DiscoveryCode!=='NO_WEB_SERVICE')console.error(refused.rows.map(r=>({target:r.Target,IP:r.IP,HTTP:r.HTTP,discovery:r.DiscoveryCode,error:r['Error code'],detail:r['Technical error'],evidence:r.Evidence})));
      check(refused.rows[0]?.DiscoveryCode==='NO_WEB_SERVICE','closed ports separated');
      check(/TCP_(REFUSED|TIMEOUT|FAILED)/.test(refused.rows[0]?.['Technical error']),'connection refusal or OS timeout diagnosed');
      check(refused.html.includes('class="no-response"'),'no-response HTML section separate');
      const timeout=await audit(engine,'slow.test=127.0.0.1',[httpPort]);
      check(/TIMEOUT/.test(timeout.rows[0]?.['Error code']),'timeout classified');
      const malformed=await audit(engine,'127.0.0.1',[rawPort]);
      if(malformed.rows[0]?.DiscoveryCode!=='CONNECTION_ERROR')console.error(malformed.rows.map(r=>({discovery:r.DiscoveryCode,error:r['Error code'],detail:r['Technical error'],evidence:r.Evidence})));
      check(malformed.rows[0]?.DiscoveryCode==='CONNECTION_ERROR','non-HTTP port not confirmed as web');
      const dns=await audit(engine,'localhost',[httpPort]);
      if(!(dns.rows[0]?.HTTP==='200'&&dns.rows[0]?.IP==='127.0.0.1'))console.error(dns.rows.map(r=>({target:r.Target,IP:r.IP,HTTP:r.HTTP,discovery:r.DiscoveryCode,error:r['Error code'],detail:r['Technical error'],evidence:r.Evidence})));
      check(dns.rows[0]?.HTTP==='200'&&dns.rows[0]?.IP==='127.0.0.1','DNS hostname resolution');
      const range=await audit(engine,'127.0.0.1-2,127.0.0.1',[closedPort]);
      check(range.rows.length===2,'IP range and deduplication preserved');
      const cidr=await audit(engine,'127.0.0.0/30',[closedPort],[],'pt');
      check(cidr.rows.length===2&&cidr.rows.every(r=>r.Descoberta==='SEM SERVIÇO WEB DETETADO'),'CIDR + Portuguese report');
      const date=new Date().toISOString().slice(0,10);
      const conservative=await simulated(engine,[
        ['192.0.2.1','example.test','Linux','PHP-FPM','process:1','-','8.3.6','php=build','NA','fictional stale proof'],
        ['192.0.2.2','example.test','Linux','PHP-FPM','process:2','-','8.3.6','-','NA','fictional incomplete backport'],
        ['192.0.2.3','example.test<script>','Linux','HTTP:80','web:80','=1+1','8.3.35','-','SIMULADO','TOKEN=DO_NOT_LEAK password=DO_NOT_LEAK Authorization: Bearer DO_NOT_LEAK']
      ],[
        ['192.0.2.1','PHP-FPM','process:1','8.3.6','php=build','FIXED','FIXED','TRUE','2000-01-01','Test','https://example.invalid/advisory'],
        ['192.0.2.2','PHP-FPM','process:2','8.3.6','-','FIXED','FIXED','TRUE',date,'Test','https://example.invalid/advisory']
      ]);
      check(conservative.rows.every(r=>r.VulnerabilityCode==='POTENTIALLY_VULNERABLE'),'stale or incomplete backport never certified');
      check(conservative.rows[2].Application==="'=1+1",'CSV formula protected');
      check(!/DO_NOT_LEAK/.test(conservative.text+conservative.html),'diagnostic secrets redacted');
      check(!conservative.html.includes('example.test<script>')&&conservative.html.includes('example.test&lt;script&gt;'),'HTML evidence escaped');
      if(!(win&&engine.id==='bash')){
        const many=[];let endpoint=0;
        for(let i=1;i<=254;i++){
          const target='198.51.100.'+i;
          if(i<=18){for(let j=0;j<(i<=6?2:1);j++){
            const failed=endpoint++<15,port=failed?443+j:80+j;
            many.push([target,'fixture.test','-',(failed?'HTTPS:':'HTTP:')+port,'web:'+port,'-','-','-','SIMULADO','FICTIONAL regression',target,failed?'CONNECTION_ERROR':'PHP_NOT_IDENTIFIED',failed?'-':'200',failed?'FAILED':'NOT_APPLICABLE',failed?'TLS_CERTIFICATE_INVALID':'-',failed?'self-signed test certificate':'-','-','LOW']);
          }}else many.push([target,'fixture.test','-','DISCOVERY','host','-','-','-','DESCONHECIDO','FICTIONAL regression',target,'NO_WEB_SERVICE','-','-','NO_TCP_RESPONSE','TCP_REFUSED','-','LOW']);
        }
        const large=await simulated(engine,many);
        check(large.rows.length===260,'254-target regression has 260 observations');
        check(new Set(large.rows.map(r=>r.Target)).size===254,'254-target count not confused with observations');
        check(large.rows.filter(r=>r.Section==='Web services and candidates').length===24,'24 candidate ports separate');
        check(large.rows.filter(r=>r['Error code']==='TLS_CERTIFICATE_INVALID').length===15,'15 TLS errors retained');
        check(large.html.includes('<strong>9</strong>HTTP/HTTPS responses'),'only 9 actual HTTP responses counted');
        check(large.html.includes('<strong>18</strong>IPs with candidate ports'),'18 candidate IPs not confused with 24 ports');
        check(large.html.includes('<strong>15</strong>Connection/collection errors'),'unknown optional fields do not become errors or redirects');
        check(large.html.includes('<strong>260</strong>Results'),'observation total shown');
      }
      if((win&&engine.id!=='bash')||(!win&&engine.id==='bash')){
        const localOut=path.join(scratch,'local-'+engine.id);
        const args=engine.id==='bash'?[snapshots['php_audit.sh'],'en','--local-inventory','--out',localOut]:['-NoProfile','-File',snapshots['PHP-Audit.ps1'],'-Language','en','-LocalInventory','-OutDir',localOut];
        await command(engine.exe,args);
        const dir=fs.readdirSync(localOut)[0],rows=csv(fs.readFileSync(path.join(localOut,dir,'report.csv'),'utf8'));
        check(rows.some(r=>r.Service==='LOCAL'&&r.Target==='local'),'local inventory without network scope');
        check(rows.every(r=>r.VulnerabilityCode!=='FIXED'),'local inventory does not certify a fixed web runtime');
      }
      process.stdout.write('PASS '+engine.id+': '+(assertions-before)+' integration assertions (+21 built-in rules; native core assertions above)\n');
    }
    console.log('PASS TOTAL: '+assertions+' integration assertions; engines='+engines.map(e=>e.id).join(','));
  }finally{
    for(const server of servers){if(server.closeAllConnections)server.closeAllConnections();server.close();}
    if(path.dirname(scratch)!==path.resolve(os.tmpdir())||!path.basename(scratch).startsWith('php-audit-tests-'))throw Error('Unexpected scratch path; cleanup refused');
    fs.rmSync(scratch,{recursive:true,force:true});
  }
})().catch(e=>{console.error(e.stack);process.exitCode=1});
