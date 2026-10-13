const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const sleep = ms => new Promise(r => setTimeout(r,ms));

const DEMO = {
  alias:'7K3M',
  secret:'atomic-commits-demo-shared-secret',
  demoWindowMs:15000,
  productionWindowMs:5*60*1000,
  txCap:50,
  monthCap:500,
  monthSpent:0,
  spent:new Set(),
  acceptedWindows:6,
  currentCode:null,
  lastSuccess:null,
  busy:false,
  view:'code'
};
const enc = new TextEncoder();
const cache = new Map();

function currentDemoWindow(){
  return currentProductionWindow();
}
function currentProductionWindow(){ return Math.floor(Date.now()/DEMO.productionWindowMs); }
function expiryMs() {
  return (currentProductionWindow() + 1) * DEMO.productionWindowMs;
}

function fmtTime(ms){
  return new Date(ms).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}
function timeLeftText(ms){
  const mins = Math.max(0, Math.ceil((ms-Date.now())/60000));
  return mins <= 1 ? 'less than 1 min left' : `${mins} min left`;
}

async function hmac(message){
  if(window.crypto && window.crypto.subtle){
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(DEMO.secret),
      {name:'HMAC',hash:'SHA-256'},
      false, ['sign']
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(message)));
  }
  let h=2166136261;
  const s=DEMO.secret+'|'+message;
  for(let i=0;i<s.length;i++){ h^=s.charCodeAt(i); h=Math.imul(h,16777619); }
  return new Uint8Array([(h>>>24)&255,(h>>>16)&255,(h>>>8)&255,h&255]);
}

async function codeForWindow(w){
  if(cache.has(w)) return cache.get(w);
  const bytes=await hmac(`${DEMO.alias}|${w}`);
  let n=0;
  for(let i=0;i<Math.min(bytes.length,6);i++) n=(n*257+bytes[i])>>>0;
  const code=String(n%1000000).padStart(6,'0');
  cache.set(w,code);
  return code;
}

function stamp(){
  const d=new Date(),p=n=>String(n).padStart(2,'0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function log(msg,cls=''){
  const row=document.createElement('div');
  row.className=cls;
  row.textContent=`${stamp()}  ${msg}`;
  $('#console').appendChild(row);
  $('#console').scrollTop=$('#console').scrollHeight;
  while($('#console').children.length>60) $('#console').removeChild($('#console').firstChild);
}

function receipt(title,detail,cls=''){
  const el=$('#verdict');
  el.className='receipt'+(cls?' '+cls:'');
  el.innerHTML=`<span class="receipt-dot"></span><div><strong>${title}</strong><small>${detail}</small></div>`;
}

function updateExpiryUi(){
  const exp=expiryMs();
  const exact=fmtTime(exp);
  $('#validUntil').textContent=`Valid until ${exact}`;
  $('#qrValidUntil').textContent=`Valid until ${exact}`;
  $('#policyExpiry').textContent=exact;
  $('#timeLeft').textContent=timeLeftText(exp);
  $('#durationHelp').textContent=DEMO.acceptedWindows===6
    ? '30 minutes is the maximum. The exact expiry time is shown above.'
    : 'Short mode accepts the current 5-minute time window plus the previous one.';
}

function renderQr(){
  const el=$('#qrCode');
  if(!DEMO.currentCode) return;
  el.innerHTML='';
  const payload=JSON.stringify({
    v:1,
    payer:DEMO.alias,
    code:DEMO.currentCode,
    maxAmount:DEMO.txCap,
    expiresAt:new Date(expiryMs()).toISOString()
  });

  if(window.QRCode){
    new QRCode(el,{
      text:payload,
      width:168,
      height:168,
      colorDark:'#171714',
      colorLight:'#fffdf8',
      correctLevel:QRCode.CorrectLevel.M
    });
  }else{
    el.textContent='QR unavailable';
  }
}

let lastRenderedCode=null;
async function tick(){
  const code=await codeForWindow(currentDemoWindow());
  DEMO.currentCode=code;
  $('#buyerCode').textContent=code;

  const remaining = DEMO.productionWindowMs - (Date.now() % DEMO.productionWindowMs);
  $('#timerFill').style.width =
  (remaining / DEMO.productionWindowMs * 100) + '%';

  updateExpiryUi();
  if(lastRenderedCode!==code){
    lastRenderedCode=code;
    renderQr();
  }
}

$$('.segmented button').forEach(btn=>{
  btn.addEventListener('click',()=>{
    $$('.segmented button').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    DEMO.acceptedWindows=Number(btn.dataset.windows);
    updateExpiryUi();
    renderQr();
  });
});

$$('.code-switch button').forEach(btn=>{
  btn.addEventListener('click',()=>{
    $$('.code-switch button').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    DEMO.view=btn.dataset.view;
    $('#codeView').classList.toggle('hidden',DEMO.view!=='code');
    $('#qrView').classList.toggle('hidden',DEMO.view!=='qr');
    if(DEMO.view==='qr') renderQr();
  });
});

$('#sendBtn').addEventListener('click',async()=>{
  const code=DEMO.currentCode || await codeForWindow(currentDemoWindow());
  $('#payerId').value=DEMO.alias;
  $('#merchantCode').value=code;

  const chip=$('#handoffChip');
  chip.innerHTML=DEMO.view==='qr'
    ? '<span>QR</span><strong>SCANNABLE</strong>'
    : `<span>${DEMO.alias}</span><strong>${code}</strong>`;

  chip.animate([
    {transform:'translateX(-20px) scale(.94)',opacity:.25},
    {transform:'translateX(0) scale(1)',opacity:1}
  ],{duration:420,easing:'cubic-bezier(.2,.8,.2,1)'});

  receipt(DEMO.view==='qr'?'QR ready at merchant':'Code received','Enter the amount, then verify and pay.','pending');
  log(`payer → merchant · ${DEMO.view==='qr'?'QR payload':DEMO.alias+' '+code}`,'dim');
});

$('#scanQrBtn').addEventListener('click',async()=>{
  const code=DEMO.currentCode || await codeForWindow(currentDemoWindow());
  $('#payerId').value=DEMO.alias;
  $('#merchantCode').value=code;
  receipt('QR scanned','Payer ID and authorization code filled automatically.','pending');
  log(`merchant · QR scanned → payer ${DEMO.alias}, code ${code}`,'dim');
});
async function verify(alias, code, count) {
  if (alias !== DEMO.alias) {
    return { ok: false, reason: 'unknown payer ID' };
  }

  if (DEMO.spent.has(`${alias}:${code}`)) {
    return { ok: false, reason: 'code already used' };
  }

  const now = currentProductionWindow();
  const expectedCode = await codeForWindow(now);

  if (expectedCode !== code) {
    return { ok: false, reason: 'code expired or invalid' };
  }

  return { ok: true, window: now };
}


function updateGrant(){
  const pct=Math.min(100,DEMO.monthSpent/DEMO.monthCap*100);
  $('#grantFill').style.width=pct+'%';
  $('#grantUsed').textContent=`R${DEMO.monthSpent.toFixed(2)} used`;
}

async function redeem(){
  if(DEMO.busy) return;
  DEMO.busy=true;
  $('#redeemBtn').disabled=true;
  $('#replayBtn').disabled=true;

  const alias=$('#payerId').value.trim().toUpperCase();
  const code=$('#merchantCode').value.trim();
  const amount=Number($('#amount').value||0);
  const wallet=$('#wallet').value.trim();

  receipt('Verifying','Checking code, replay state and payment limits…','pending');
  log(`POST /redeem { payer:${alias}, code:${code}, amount:R${amount.toFixed(2)} }`);
  await sleep(280);

 
  let paymentResponse;
  let paymentResult;

  try {
    paymentResponse = await fetch('/api/payments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        payerId: alias,
        code,
        amount,
        wallet
      })
    });

    paymentResult = await paymentResponse.json();
  } catch (error) {
    console.error('Payment request failed:', error);
    log(`payment error · ${error.message}`, 'bad');
    receipt('Payment request failed', 'Could not contact the server.', 'bad');
    finish();
    return;
  }

  if (!paymentResponse.ok) {
    const message = paymentResult.error || paymentResult.reason || 'Payment rejected.';
    log(`reject · ${message}`, 'bad');
    receipt(
      paymentResponse.status === 401 ? 'Login required' : 'Payment rejected',
      message,
      'bad'
    );
    finish();
    return;
  }

  DEMO.monthSpent = paymentResult.monthlySpent;
  DEMO.spent.add(`${alias}:${code}`);
  updateGrant();


  if(amount<=0 || amount>DEMO.txCap){
    log(`policy · amount exceeds R${DEMO.txCap} code limit`,'bad');
    receipt('Payment rejected',`This code is limited to R${DEMO.txCap}.`,'bad');
    finish();return;
  }

  if(DEMO.monthSpent+amount>DEMO.monthCap){
    log('grant · monthly Open Payments permission would be exceeded','bad');
    receipt('Payment rejected','The payer’s monthly Open Payments permission has no remaining capacity.','bad');
    finish();return;
  }

  if(!wallet){
    log('merchant · wallet address missing','bad');
    receipt('Payment rejected','Merchant wallet address is missing.','bad');
    finish();return;
  }

 
DEMO.lastSuccess = { alias, code, amount, wallet };

log('complete · demo payment record saved on server', 'ok');
receipt(
  'Demo payment recorded',
  `R${amount.toFixed(2)} recorded for ${wallet}. No real money was transferred.`,
  'ok'
);
finish(true);

  function finish(success=false){
    DEMO.busy=false;
    $('#redeemBtn').disabled=false;
    $('#replayBtn').disabled=!(success||DEMO.lastSuccess);
  }
}

$('#redeemBtn').addEventListener('click',redeem);
$('#replayBtn').addEventListener('click',()=>{
  if(!DEMO.lastSuccess) return;
  $('#payerId').value=DEMO.lastSuccess.alias;
  $('#merchantCode').value=DEMO.lastSuccess.code;
  $('#amount').value=DEMO.lastSuccess.amount.toFixed(2);
  $('#wallet').value=DEMO.lastSuccess.wallet;
  redeem();
});

function updateCost(){
  const perDay=Number($('#txnSlider').value);
  const perMonth=perDay*30;
  const mb=perMonth*10/1000;
  const cost=perMonth/1000*2;
  $('#txnLabel').textContent=perDay;
  $('#dataOut').textContent=(mb<10?mb.toFixed(1):Math.round(mb))+' MB';
  $('#costOut').textContent='R'+(cost<10?cost.toFixed(2):cost.toFixed(1));
}

$('#txnSlider').addEventListener('input',updateCost);
updateCost();
updateGrant();
tick();
setInterval(tick,200);
log('setup · payer secret registered with Atomic Commits','dim');
log('grant · payer approved R500/month outgoing-payment permission','dim');
