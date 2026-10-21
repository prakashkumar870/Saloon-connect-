const express=require('express'),D=require('better-sqlite3'),bc=require('bcryptjs'),jwt=require('jsonwebtoken');
const db=new D(process.env.DB_PATH||'salon.db'),SECRET=process.env.JWT_SECRET||'dev-secret-change';
db.exec(`create table if not exists users(id integer primary key,name text,email text unique,pass text,role text);
create table if not exists salons(id integer primary key,owner_id integer,name text,image text default '',address text default '',city text default '',pin text default '',hours text default '',lat real,lng real,approved integer default 0,active integer default 1,sub_until text);
create table if not exists services(id integer primary key,salon_id integer,name text,price real);`);
const {ADMIN_EMAIL:AE,ADMIN_PASSWORD:AP}=process.env;
if(AE&&AP&&!db.prepare('select 1 from users where email=?').get(AE))db.prepare('insert into users(name,email,pass,role) values(?,?,?,?)').run('Super Admin',AE,bc.hashSync(AP,10),'admin');
const app=express();app.use(express.json({limit:'100kb'}),express.static('public'));
const bad=(m,s=400)=>{const e=Error(m);e.s=s;throw e};
const wrap=f=>(q,r)=>{try{f(q,r)}catch(e){r.status(e.s||500).json({error:e.s?e.message:'Server error'})}};
const auth=role=>(q,r,n)=>{try{q.u=jwt.verify((q.headers.authorization||'').slice(7),SECRET);if(role&&q.u.role!==role)return r.status(403).json({error:'Forbidden'});n()}catch{r.status(401).json({error:'Login required'})}};
const sign=u=>({token:jwt.sign({id:u.id,role:u.role},SECRET,{expiresIn:'7d'}),user:{name:u.name,role:u.role}});
const okc=(a,b)=>Number.isFinite(a)&&Number.isFinite(b)&&Math.abs(a)<=90&&Math.abs(b)<=180;
const today=()=>new Date().toISOString().slice(0,10);
const km=(a,b,c,d)=>{const t=x=>x*Math.PI/180,h=Math.sin(t(c-a)/2)**2+Math.cos(t(a))*Math.cos(t(c))*Math.sin(t(d-b)/2)**2;return 12742*Math.asin(Math.sqrt(h))};
app.post('/api/register',wrap((q,r)=>{const{name,email,password,role}=q.body;
if(!name||!email||String(password||'').length<8)bad('Name, email and 8+ char password required');
if(!['customer','owner'].includes(role))bad('Invalid role');
if(db.prepare('select 1 from users where email=?').get(email))bad('Email already used');
const id=db.prepare('insert into users(name,email,pass,role) values(?,?,?,?)').run(name,email,bc.hashSync(password,10),role).lastInsertRowid;
if(role=='owner')db.prepare('insert into salons(owner_id,name) values(?,?)').run(id,'New Salon');
r.json(sign({id,name,role}))}));
app.post('/api/login',wrap((q,r)=>{const u=db.prepare('select * from users where email=?').get(q.body.email);
if(!u||!bc.compareSync(String(q.body.password||''),u.pass))bad('Wrong email or password',401);r.json(sign(u))}));
// Public search: location is used only to compute distance; never stored or logged.
app.get('/api/nearby',wrap((q,r)=>{const lat=+q.query.lat,lng=+q.query.lng,rad=+q.query.radius||5;if(!okc(lat,lng))bad('Invalid location');
const rows=db.prepare('select * from salons where approved=1 and active=1 and lat is not null and lng is not null and sub_until>=?').all(today());
const sv=db.prepare('select name,price from services where salon_id=?');
r.json(rows.map(s=>({...s,distance:km(lat,lng,s.lat,s.lng)})).filter(s=>s.distance<=rad).sort((a,b)=>a.distance-b.distance)
.map(({owner_id,approved,active,sub_until,...s})=>({...s,distance:+s.distance.toFixed(2),services:sv.all(s.id)})))}));
const mine=q=>db.prepare('select * from salons where owner_id=?').get(q.u.id);
app.get('/api/my-salon',auth('owner'),wrap((q,r)=>{const s=mine(q);r.json({...s,services:db.prepare('select * from services where salon_id=?').all(s.id)})}));
app.put('/api/my-salon',auth('owner'),wrap((q,r)=>{const b=q.body,s=mine(q),t=k=>String(b[k]??'').trim().slice(0,200);
const lat=b.lat===''||b.lat==null?null:+b.lat,lng=b.lng===''||b.lng==null?null:+b.lng;
if((lat==null)!=(lng==null)||(lat!=null&&!okc(lat,lng)))bad('Invalid latitude/longitude');
if(t('image')&&!/^https?:\/\//.test(t('image')))bad('Image must be an http(s) link');
if(!t('name'))bad('Name required');if(t('pin')&&!/^\d{6}$/.test(t('pin')))bad('PIN must be 6 digits');
const moved=lat!==s.lat||lng!==s.lng||t('address')!==s.address;
db.prepare('update salons set name=?,image=?,address=?,city=?,pin=?,hours=?,lat=?,lng=?,approved=? where id=?').run(t('name'),t('image'),t('address'),t('city'),t('pin'),t('hours'),lat,lng,moved?0:s.approved,s.id);
r.json({ok:1,reapproval:moved&&!!s.approved})}));
app.post('/api/my-salon/services',auth('owner'),wrap((q,r)=>{const p=+q.body.price,n=String(q.body.name||'').trim().slice(0,100);if(!n||!(p>=0))bad('Valid name and price required');
db.prepare('insert into services(salon_id,name,price) values(?,?,?)').run(mine(q).id,n,p);r.json({ok:1})}));
app.delete('/api/my-salon/services/:id',auth('owner'),wrap((q,r)=>{db.prepare('delete from services where id=? and salon_id=?').run(q.params.id,mine(q).id);r.json({ok:1})}));
app.get('/api/admin/salons',auth('admin'),wrap((q,r)=>r.json(db.prepare('select s.*,u.name owner from salons s join users u on u.id=s.owner_id order by s.id desc').all())));
app.post('/api/admin/salons/:id',auth('admin'),wrap((q,r)=>{const s=db.prepare('select * from salons where id=?').get(q.params.id);if(!s)bad('Not found',404);const b=q.body;
if('approved' in b){if(b.approved&&!okc(s.lat,s.lng))bad('Salon has no valid coordinates');db.prepare('update salons set approved=? where id=?').run(b.approved?1:0,s.id)}
if('active' in b)db.prepare('update salons set active=? where id=?').run(b.active?1:0,s.id);
if(b.extend){const d=s.sub_until&&s.sub_until>today()?new Date(s.sub_until):new Date();d.setDate(d.getDate()+30);db.prepare('update salons set sub_until=? where id=?').run(d.toISOString().slice(0,10),s.id)}
r.json({ok:1})}));
const parseLL=u=>{const m=u.match(/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/)||u.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/)||u.match(/[?&](?:q|ll|query|destination)=(-?\d+\.\d+)(?:,|%2C)(-?\d+\.\d+)/);return m&&okc(+m[1],+m[2])?{lat:+m[1],lng:+m[2]}:null};
const okHost=h=>/^(maps\.app\.goo\.gl|goo\.gl|(www\.)?google\.[a-z.]+|maps\.google\.[a-z.]+)$/.test(h);
// Owner pastes a Google Maps link; only Google hosts are followed (no open redirects/SSRF)
app.post('/api/resolve-map-link',auth('owner'),async(q,r)=>{try{let u=String(q.body.url||'').trim();
for(let i=0;i<5;i++){const x=new URL(u);if(x.protocol!=='https:'||!okHost(x.hostname))break;const p=parseLL(decodeURIComponent(u));if(p)return r.json(p);
const res=await fetch(u,{redirect:'manual',headers:{'User-Agent':'Mozilla/5.0'}});const loc=res.headers.get('location');if(!loc)break;u=new URL(loc,u).href}
r.status(400).json({error:'Coordinates not found in this link. Open the exact place in Google Maps, tap Share, and paste that link.'})}catch{r.status(400).json({error:'Invalid link'})}});
app.listen(process.env.PORT||3000,()=>console.log('Salon Connect running'));
