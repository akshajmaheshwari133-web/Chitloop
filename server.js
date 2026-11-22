require('dotenv').config();
const express=require('express'),path=require('path'),crypto=require('crypto'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),Database=require('better-sqlite3'),rateLimit=require('express-rate-limit'),nodemailer=require('nodemailer');
const E=process.env,PORT=E.PORT||3000;
if(!E.JWT_SECRET||E.JWT_SECRET.length<24){console.error('Set JWT_SECRET (24+ chars) in .env');process.exit(1)}
const db=new Database(E.DB_PATH||'chitloop.db');db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,login TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,pass_hash TEXT NOT NULL,verified INTEGER DEFAULT 0,created INTEGER);
CREATE TABLE IF NOT EXISTS codes(login TEXT PRIMARY KEY,code_hash TEXT,expires INTEGER,attempts INTEGER DEFAULT 0,last_sent INTEGER);
CREATE TABLE IF NOT EXISTS contacts(a INTEGER,b INTEGER,UNIQUE(a,b));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,from_id INTEGER,to_id INTEGER,text TEXT,reply TEXT,ts INTEGER);
CREATE INDEX IF NOT EXISTS m_to ON messages(to_id,id);CREATE INDEX IF NOT EXISTS m_from ON messages(from_id,id);`);
for(const c of ['totp_secret TEXT','totp_on INTEGER DEFAULT 0','totp_last INTEGER DEFAULT 0','recovery TEXT'])try{db.exec('ALTER TABLE users ADD COLUMN '+c)}catch{}
const QR=require('qrcode');
const mailer=E.SMTP_HOST?nodemailer.createTransport({host:E.SMTP_HOST,port:+E.SMTP_PORT||587,auth:{user:E.SMTP_USER,pass:E.SMTP_PASS}}):null;
const sms=(E.TWILIO_SID&&E.TWILIO_TOKEN&&E.TWILIO_FROM)?require('twilio')(E.TWILIO_SID,E.TWILIO_TOKEN):null;
const bad=(res,c,m,x)=>res.status(c).json({error:m,...x});
function norm(kind,v){v=String(v||'').trim();if(kind==='email'){v=v.toLowerCase();return /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(v)&&v.length<=254?v:null}
 if(kind==='phone'){v='+'+v.replace(/\D/g,'');return /^\+[1-9]\d{7,14}$/.test(v)?v:null}return null}
const guess=v=>String(v).includes('@')?'email':'phone';
const mask=(k,l)=>k==='email'?l.replace(/^(.).*(@.*)$/,'$1•••$2'):'••••'+l.slice(-4);
const hc=(l,c)=>crypto.createHash('sha256').update(c+'|'+l+'|'+E.JWT_SECRET).digest('hex');
async function deliver(kind,login,code){const text=`Your Chitloop verification code is ${code}. It expires in 10 minutes. Don't share it with anyone.`;
 if(kind==='email'&&mailer)return mailer.sendMail({from:E.MAIL_FROM||E.SMTP_USER,to:login,subject:`${code} is your Chitloop code`,text});
 if(kind==='phone'&&sms)return sms.messages.create({from:E.TWILIO_FROM,to:login,body:text});
 if(E.DEV_LOG_CODES){console.log(`[DEV] code for ${login}: ${code}`);return}
 throw new Error(kind==='email'?'Email sending is not configured on the server':'SMS sending is not configured on the server')}
async function issueCode(user){const row=db.prepare('SELECT last_sent FROM codes WHERE login=?').get(user.login),now=Date.now();
 if(row&&now-row.last_sent<60000)throw Object.assign(new Error('Please wait a minute before requesting another code'),{status:429});
 const code=String(crypto.randomInt(0,1e6)).padStart(6,'0');
 await deliver(user.kind,user.login,code);
 db.prepare('INSERT INTO codes(login,code_hash,expires,attempts,last_sent) VALUES(?,?,?,0,?) ON CONFLICT(login) DO UPDATE SET code_hash=excluded.code_hash,expires=excluded.expires,attempts=0,last_sent=excluded.last_sent').run(user.login,hc(user.login,code),now+600000,now)}
const pub=u=>({id:u.id,name:u.name,login:u.login,kind:u.kind,twofa:!!u.totp_on});
const sign=u=>jwt.sign({id:u.id},E.JWT_SECRET,{expiresIn:'30d'});
function auth(req,res,next){try{const t=(req.headers.authorization||'').replace('Bearer ','');const p=jwt.verify(t,E.JWT_SECRET);if(p.step)throw 0;const id=p.id;const u=db.prepare('SELECT * FROM users WHERE id=? AND verified=1').get(id);if(!u)throw 0;req.user=u;next()}catch{bad(res,401,'Please log in again')}}

// ---- Two-step verification (TOTP, RFC 6238) + recovery codes
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32=buf=>{let bits='',o='';for(const b of buf)bits+=b.toString(2).padStart(8,'0');for(let i=0;i<bits.length;i+=5)o+=B32[parseInt(bits.slice(i,i+5).padEnd(5,'0'),2)];return o};
const unb32=t=>{let bits='';for(const c of t)bits+=B32.indexOf(c).toString(2).padStart(5,'0');const a=[];for(let i=0;i+8<=bits.length;i+=8)a.push(parseInt(bits.slice(i,i+8),2));return Buffer.from(a)};
const hotp=(sec,ctr)=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(ctr));const h=crypto.createHmac('sha1',unb32(sec)).update(b).digest(),o=h[19]&15;return String(((h[o]&127)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3])%1e6).padStart(6,'0')};
function checkTotp(u,code){code=String(code||'').replace(/\s/g,'');if(!u.totp_secret||!/^\d{6}$/.test(code))return false;const st=Math.floor(Date.now()/30000);
 for(const d of [-1,0,1]){const x=st+d;if(x>(u.totp_last||0)&&hotp(u.totp_secret,x)===code){db.prepare('UPDATE users SET totp_last=? WHERE id=?').run(x,u.id);return true}}return false}
const rh=c=>crypto.createHash('sha256').update(c+'|r|'+E.JWT_SECRET).digest('hex');
function useRecovery(u,code){const c=String(code||'').trim().toLowerCase();if(!/^[0-9a-f]{4}-[0-9a-f]{4}$/.test(c))return false;const l=JSON.parse(u.recovery||'[]'),i=l.indexOf(rh(c));if(i<0)return false;l.splice(i,1);db.prepare('UPDATE users SET recovery=? WHERE id=?').run(JSON.stringify(l),u.id);return true}
const secondFactor=(u,c)=>checkTotp(u,c)||useRecovery(u,c);
const fails=new Map(),locked=id=>{const f=fails.get(id);return f&&f.n>=5&&Date.now()<f.until},fail=id=>{const f=fails.get(id)||{n:0};f.n++;f.until=Date.now()+900000;fails.set(id,f)};
const http=require('http'),{WebSocketServer}=require('ws');
const clients=new Map();
const push=(id,o)=>{const s=clients.get(+id);if(!s)return 0;const j=JSON.stringify(o);s.forEach(w=>w.readyState===1&&w.send(j));return s.size};
function codeErr(l,code){const c=db.prepare('SELECT * FROM codes WHERE login=?').get(l);if(!c||Date.now()>c.expires)return 'Code expired. Request a new one.';if(c.attempts>=5)return 'Too many attempts. Request a new code.';
 db.prepare('UPDATE codes SET attempts=attempts+1 WHERE login=?').run(l);const a=Buffer.from(hc(l,String(code||'').trim())),b=Buffer.from(c.code_hash);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return 'Incorrect code';db.prepare('DELETE FROM codes WHERE login=?').run(l);return null}
const tick=(t,step)=>{try{const p=jwt.verify(String(t||''),E.JWT_SECRET);return p.step===step?p:null}catch{return null}};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'20kb'}));
const lim=rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false});
const wrap=f=>(q,r)=>f(q,r).catch(e=>bad(r,e.status||500,e.status?e.message:(console.error(e),e.message.includes('not configured')?e.message:'Could not send the code. Try again later.')));
app.post('/api/signup',lim,wrap(async(req,res)=>{const {name,kind,login,password}=req.body||{};const k=kind==='phone'?'phone':'email',l=norm(k,login);
 if(!l)return bad(res,400,k==='email'?'Enter a valid email address':'Enter your number with country code, e.g. +919876543210');
 if(!name||String(name).trim().length<2)return bad(res,400,'Enter your name');if(!password||password.length<8)return bad(res,400,'Password must be at least 8 characters');
 const ex=db.prepare('SELECT * FROM users WHERE login=?').get(l);if(ex&&ex.verified)return bad(res,409,'An account with this '+k+' already exists. Log in instead.');
 const h=bcrypt.hashSync(password,11),n=String(name).trim().slice(0,40);
 if(ex)db.prepare('UPDATE users SET name=?,pass_hash=? WHERE id=?').run(n,h,ex.id);else db.prepare('INSERT INTO users(name,login,kind,pass_hash,created) VALUES(?,?,?,?,?)').run(n,l,k,h,Date.now());
 await issueCode({login:l,kind:k});res.json({login:l,hint:mask(k,l)})}));
app.post('/api/resend',lim,wrap(async(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE login=? AND verified=0').get(String(req.body?.login||''));if(u)await issueCode(u);res.json({ok:true})}));
app.post('/api/verify',lim,wrap(async(req,res)=>{const l=String(req.body?.login||''),code=String(req.body?.code||'').trim();
 const u=db.prepare('SELECT * FROM users WHERE login=?').get(l),c=db.prepare('SELECT * FROM codes WHERE login=?').get(l);
 if(!u||!c||Date.now()>c.expires)return bad(res,400,'Code expired. Request a new one.');
 if(c.attempts>=5)return bad(res,429,'Too many attempts. Request a new code.');
 db.prepare('UPDATE codes SET attempts=attempts+1 WHERE login=?').run(l);
 const a=Buffer.from(hc(l,code)),b=Buffer.from(c.code_hash);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return bad(res,400,'Incorrect code');
 db.prepare('UPDATE users SET verified=1 WHERE id=?').run(u.id);db.prepare('DELETE FROM codes WHERE login=?').run(l);res.json({token:sign(u),user:pub(u)})}));
app.post('/api/login',lim,wrap(async(req,res)=>{const raw=String(req.body?.login||''),l=norm(guess(raw),raw);const u=l&&db.prepare('SELECT * FROM users WHERE login=?').get(l);
 if(!u||!bcrypt.compareSync(String(req.body?.password||''),u.pass_hash))return bad(res,401,'Incorrect login or password');
 if(!u.verified){await issueCode(u).catch(()=>{});return bad(res,403,'Verify your account to continue',{needsVerify:true,login:u.login,hint:mask(u.kind,u.login)})}
 if(E.LOGIN_CODE!=='0'){await issueCode(u).catch(e=>{if(e.status!==429)throw e});return res.json({needCode:true,hint:mask(u.kind,u.login),ticket:jwt.sign({id:u.id,step:'code'},E.JWT_SECRET,{expiresIn:'10m'})})}
 if(u.totp_on)return res.json({need2fa:true,ticket:jwt.sign({id:u.id,step:'2fa'},E.JWT_SECRET,{expiresIn:'5m'})});
 res.json({token:sign(u),user:pub(u)})}));
app.post('/api/login/code',lim,wrap(async(req,res)=>{const p=tick(req.body?.ticket,'code'),u=p&&db.prepare('SELECT * FROM users WHERE id=? AND verified=1').get(p.id);if(!u)return bad(res,401,'Session expired. Log in again.');
 const e=codeErr(u.login,req.body?.code);if(e)return bad(res,400,e);
 if(u.totp_on)return res.json({need2fa:true,ticket:jwt.sign({id:u.id,step:'2fa'},E.JWT_SECRET,{expiresIn:'5m'})});res.json({token:sign(u),user:pub(u)})}));
app.post('/api/login/resend',lim,wrap(async(req,res)=>{const p=tick(req.body?.ticket,'code'),u=p&&db.prepare('SELECT * FROM users WHERE id=? AND verified=1').get(p.id);if(u)await issueCode(u);res.json({ok:true})}));
app.get('/api/me',auth,(req,res)=>res.json({user:pub(req.user)}));
app.post('/api/contacts',auth,(req,res)=>{const raw=String(req.body?.login||''),l=norm(guess(raw),raw),t=l&&db.prepare('SELECT * FROM users WHERE login=? AND verified=1').get(l);
 if(!t)return bad(res,404,'No Chitloop account found for that email/number. Invite them to join!');if(t.id===req.user.id)return bad(res,400,'That is your own account');
 const ins=db.prepare('INSERT OR IGNORE INTO contacts(a,b) VALUES(?,?)');ins.run(req.user.id,t.id);ins.run(t.id,req.user.id);res.json({user:pub(t)})});
app.get('/api/sync',auth,(req,res)=>{const me=req.user.id,since=+req.query.since||0;
 const contacts=db.prepare('SELECT u.id,u.name,u.login,u.kind FROM contacts c JOIN users u ON u.id=c.b WHERE c.a=?').all(me);
 const messages=db.prepare('SELECT * FROM messages WHERE id>? AND (from_id=? OR to_id=?) ORDER BY id LIMIT 500').all(since,me,me);res.json({contacts,messages})});
app.post('/api/messages',auth,(req,res)=>{const to=+req.body?.to,text=String(req.body?.text||'').trim().slice(0,4000);
 if(!text||!db.prepare('SELECT 1 FROM contacts WHERE a=? AND b=?').get(req.user.id,to))return bad(res,400,'Cannot send this message');
 const ts=Date.now(),r=db.prepare('INSERT INTO messages(from_id,to_id,text,reply,ts) VALUES(?,?,?,?,?)').run(req.user.id,to,text,req.body.reply?String(req.body.reply).slice(0,200):null,ts);
 push(to,{t:'sync'});res.json({message:{id:r.lastInsertRowid,from_id:req.user.id,to_id:to,text,reply:req.body.reply||null,ts}})});

app.post('/api/login/2fa',lim,wrap(async(req,res)=>{let p;try{p=jwt.verify(String(req.body?.ticket||''),E.JWT_SECRET);if(p.step!=='2fa')throw 0}catch{return bad(res,401,'Session expired. Log in again.')}
 const u=db.prepare('SELECT * FROM users WHERE id=? AND totp_on=1 AND verified=1').get(p.id);if(!u)return bad(res,401,'Session expired. Log in again.');
 if(locked(u.id))return bad(res,429,'Too many wrong codes. Try again in 15 minutes.');
 if(!secondFactor(u,req.body?.code)){fail(u.id);return bad(res,400,'Incorrect code')}fails.delete(u.id);res.json({token:sign(u),user:pub(u)})}));
app.post('/api/2fa/setup',auth,wrap(async(req,res)=>{if(req.user.totp_on)return bad(res,400,'Two-step verification is already on');
 const sec=b32(crypto.randomBytes(20));db.prepare('UPDATE users SET totp_secret=?,totp_last=0 WHERE id=?').run(sec,req.user.id);
 const uri=`otpauth://totp/Chitloop:${encodeURIComponent(req.user.login)}?secret=${sec}&issuer=Chitloop&digits=6&period=30`;res.json({secret:sec,qr:await QR.toDataURL(uri,{margin:1,width:220})})}));
app.post('/api/2fa/enable',auth,wrap(async(req,res)=>{const u=req.user;if(u.totp_on)return bad(res,400,'Already on');if(locked(u.id))return bad(res,429,'Too many wrong codes. Try again later.');
 if(!checkTotp(u,req.body?.code)){fail(u.id);return bad(res,400,'Incorrect code. Check the time on your phone and try again.')}fails.delete(u.id);
 const codes=Array.from({length:8},()=>crypto.randomBytes(2).toString('hex')+'-'+crypto.randomBytes(2).toString('hex'));
 db.prepare('UPDATE users SET totp_on=1,recovery=? WHERE id=?').run(JSON.stringify(codes.map(rh)),u.id);res.json({recovery:codes})}));
app.post('/api/2fa/disable',auth,wrap(async(req,res)=>{const u=req.user;if(!u.totp_on)return bad(res,400,'Two-step verification is off');if(locked(u.id))return bad(res,429,'Too many wrong attempts. Try again later.');
 if(!bcrypt.compareSync(String(req.body?.password||''),u.pass_hash)||!secondFactor(u,req.body?.code)){fail(u.id);return bad(res,400,'Incorrect password or code')}fails.delete(u.id);
 db.prepare('UPDATE users SET totp_on=0,totp_secret=NULL,recovery=NULL WHERE id=?').run(u.id);res.json({ok:true})}));
const PERS={nexy:'cheerful, energetic and enthusiastic',sam:'cool, calm, laid-back and reassuring',ava:'creative, playful and full of imaginative ideas',leo:'upbeat, motivating and full of good vibes'};
const aiLim=rateLimit({windowMs:15*60*1000,max:80,standardHeaders:true,legacyHeaders:false});
app.post('/api/ai',aiLim,async(req,res)=>{try{
 if(!E.ANTHROPIC_API_KEY)return bad(res,503,'AI is not configured');
 if(E.ALLOW_DEMO_AI==='0'&&!(req.headers.authorization||''))return bad(res,401,'Log in first');
 const pk=PERS[req.body?.persona]?req.body.persona:'nexy',voice=!!req.body?.voice,name=pk[0].toUpperCase()+pk.slice(1);
 const msgs=(Array.isArray(req.body?.messages)?req.body.messages:[]).slice(-12).map(m=>({role:m?.role==='assistant'?'assistant':'user',content:String(m?.content||'').slice(0,600)})).filter(m=>m.content);
 while(msgs.length&&msgs[0].role!=='user')msgs.shift();if(!msgs.length||msgs[msgs.length-1].role!=='user')return bad(res,400,'Nothing to answer');
 const system=`You are ${name}, an AI companion inside the Chitloop messaging app. Personality: ${PERS[pk]}. You are an AI; never claim to be human, but be warm, natural and genuinely helpful. Speak casual, natural American English with contractions and the occasional light filler like oh or hmm; avoid British slang and spellings. `+(voice?'This is a live voice call: answer in one or two short spoken sentences (under 35 words). No emoji, no markdown, no lists.':'This is a text chat: answer in one to three short casual sentences, at most one emoji.');
 const r=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'x-api-key':E.ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01','content-type':'application/json'},body:JSON.stringify({model:E.AI_MODEL||'claude-sonnet-5-5',max_tokens:voice?120:220,system,messages:msgs})});
 if(!r.ok){console.error('AI error',r.status,await r.text().catch(()=>''));return bad(res,502,'AI is unavailable')}
 const j=await r.json();res.json({text:(j.content||[]).filter(c=>c.type==='text').map(c=>c.text).join('').trim()})}catch(e){console.error(e);bad(res,502,'AI is unavailable')}});
app.use(express.static(path.join(__dirname,'public')));
app.get('/api/ice',auth,(req,res)=>{const l=[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}];if(E.TURN_URL)l.push({urls:E.TURN_URL.split(','),username:E.TURN_USER,credential:E.TURN_PASS});res.json({iceServers:l})});
const server=http.createServer(app),wss=new WebSocketServer({server,path:'/ws',maxPayload:65536});
wss.on('connection',ws=>{let uid=null;const t=setTimeout(()=>{if(!uid)ws.close()},10000);ws.isAlive=true;ws.on('pong',()=>{ws.isAlive=true});
 ws.on('message',raw=>{let m;try{m=JSON.parse(raw)}catch{return}
  if(!uid){if(m.t!=='auth')return;try{const p=jwt.verify(String(m.token||''),E.JWT_SECRET);if(p.step)throw 0;const u=db.prepare('SELECT id FROM users WHERE id=? AND verified=1').get(p.id);if(!u)throw 0;uid=u.id;clearTimeout(t);if(!clients.has(uid))clients.set(uid,new Set());clients.get(uid).add(ws);ws.send('{"t":"ready"}')}catch{ws.close()}return}
  if(m.t==='call'&&['offer','answer','ice','end','decline'].includes(m.k)){const to=+m.to;if(!to||!db.prepare('SELECT 1 FROM contacts WHERE a=? AND b=?').get(uid,to))return;
   const me=db.prepare('SELECT name FROM users WHERE id=?').get(uid);
   const n=push(to,{t:'call',k:m.k,from:uid,fromName:me.name,callId:String(m.callId||'').slice(0,40),media:m.media==='Video'?'Video':'Voice',data:m.data});
   if(!n&&m.k==='offer')ws.send(JSON.stringify({t:'call',k:'unavailable',from:to,callId:m.callId}))}});
 ws.on('close',()=>{clearTimeout(t);const x=uid&&clients.get(uid);if(x){x.delete(ws);if(!x.size)clients.delete(uid)}})});
setInterval(()=>wss.clients.forEach(w=>{if(!w.isAlive)return w.terminate();w.isAlive=false;w.ping()}),30000);
server.listen(PORT,()=>console.log('Chitloop running on http://localhost:'+PORT+(mailer?'':' (email: not configured)')+(sms?'':' (sms: not configured)')));
