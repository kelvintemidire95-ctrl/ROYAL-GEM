
const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const db = new Database("royal-gem.db");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const ADMIN = process.env.ADMIN_ID || "8243824380";
const TOKEN = process.env.BOT_TOKEN || "";
const PORT = process.env.PORT || 3000;

const MIN = Number(process.env.MIN_WITHDRAW || 0.01);
const DAILY = Number(process.env.DAILY_REWARD || 0.001);
const REF = Number(process.env.REFERRAL_REWARD || 0.002);

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY,
 username TEXT,
 balance REAL DEFAULT 0,
 wallet TEXT DEFAULT '',
 referrals INTEGER DEFAULT 0,
 referred_by TEXT,
 blocked INTEGER DEFAULT 0,
 daily TEXT
);

CREATE TABLE IF NOT EXISTS tasks(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT,
 reward REAL,
 link TEXT,
 active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS channels(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT,
 active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS submissions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id TEXT,
 task_id INTEGER,
 proof TEXT,
 status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS withdrawals(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id TEXT,
 amount REAL,
 wallet TEXT,
 method TEXT DEFAULT 'manual',
 status TEXT DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id TEXT,
 amount REAL,
 note TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

function verify(initData) {
 if (!TOKEN || !initData) return null;

 try {
  const p = new URLSearchParams(initData);
  const hash = p.get("hash");
  if (!hash) return null;
  p.delete("hash");

  const data = [...p.entries()]
   .sort(([a], [b]) => a.localeCompare(b))
   .map(([k,v]) => `${k}=${v}`).join("\n");

  const secret = crypto.createHmac("sha256", "WebAppData")
   .update(TOKEN).digest();

  const calculated = crypto.createHmac("sha256", secret)
   .update(data).digest("hex");

  const a = Buffer.from(calculated, "hex");
  const b = Buffer.from(hash, "hex");

  if (a.length !== b.length || !crypto.timingSafeEqual(a,b))
   return null;

  if (Date.now()/1000 - Number(p.get("auth_date")) > 3600)
   return null;

  return JSON.parse(p.get("user") || "{}");
 } catch {
  return null;
 }

}

function auth(req,res,next) {
 const u = verify(req.headers["x-telegram-init-data"]);
 if (!u?.id) return res.status(401).json({error:"Open through Telegram."});

 const id = String(u.id);
 let user = db.prepare("SELECT * FROM users WHERE id=?").get(id);

 if (!user) {
  const start = String(req.headers["x-start-param"] || "");
  const referrer = start.startsWith("ref_") ? start.slice(4) : null;

  db.prepare("INSERT INTO users(id,username,referred_by) VALUES(?,?,?)")
   .run(id,u.username || u.first_name || "Member",referrer);

  if (referrer && referrer !== id) {
   const refUser = db.prepare("SELECT id FROM users WHERE id=?").get(referrer);
   if (refUser) {
    db.prepare("UPDATE users SET referrals=referrals+1 WHERE id=?")
     .run(referrer);
   }
  }

  user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
 }

 if (user.blocked) return res.status(403).json({error:"Account blocked."});

 req.uid = id;
 next();
}

function admin(req,res,next) {
 if (req.uid !== ADMIN) return res.status(403).json({error:"Admin access denied"});
 next();
}

function credit(uid,amount,note) {
 db.transaction(() => {
  db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(amount,uid);
  db.prepare("INSERT INTO transactions(user_id,amount,note) VALUES(?,?,?)")
   .run(uid,amount,note);
 })();
}

app.get("/api/me",auth,(req,res) => {
 res.json({
  user:db.prepare("SELECT * FROM users WHERE id=?").get(req.uid),
  tasks:db.prepare("SELECT * FROM tasks WHERE active=1").all(),
  channels:db.prepare("SELECT * FROM channels WHERE active=1").all(),
  withdrawals:db.prepare("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC").all(req.uid),
  transactions:db.prepare("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.uid),
  isAdmin:req.uid===ADMIN
 });
});

app.post("/api/wallet",auth,(req,res) => {
 const wallet=String(req.body.wallet || "").trim();

 if (!/^(EQ|UQ|0Q|kQ)[A-Za-z0-9_-]{46,60}$/.test(wallet))
  return res.status(400).json({error:"Enter a valid TON address."});

 db.prepare("UPDATE users SET wallet=? WHERE id=?").run(wallet,req.uid);
 res.json({success:true});
});

app.post("/api/daily",auth,(req,res) => {
 const today=new Date().toISOString().slice(0,10);
 const user=db.prepare("SELECT * FROM users WHERE id=?").get(req.uid);

 if (user.daily===today)
  return res.status(400).json({error:"Daily reward already claimed."});

 db.transaction(() => {
  db.prepare("UPDATE users SET balance=balance+?,daily=? WHERE id=?")
   .run(DAILY,today,req.uid);
  db.prepare("INSERT INTO transactions(user_id,amount,note) VALUES(?,?,?)")
   .run(req.uid,DAILY,"Daily reward");
 })();

 res.json({success:true,reward:DAILY});
});

app.post("/api/task",auth,(req,res) => {
 const task=db.prepare("SELECT * FROM tasks WHERE id=? AND active=1")
  .get(Number(req.body.taskId));
 const proof=String(req.body.proof || "").trim();

 if (!task || !proof) return res.status(400).json({error:"Invalid task."});

 try {
  db.prepare("INSERT INTO submissions(user_id,task_id,proof) VALUES(?,?,?)")
   .run(req.uid,task.id,proof);
 } catch {
  return res.status(409).json({error:"Already submitted."});
 }

 res.json({success:true,message:"Sent for admin approval."});
});

app.post("/api/withdraw",auth,(req,res) => {
 const amount=Number(req.body.amount);
 const method=req.body.method==="automatic"?"automatic":"manual";
 const user=db.prepare("SELECT * FROM users WHERE id=?").get(req.uid);

 if (!user.wallet) return res.status(400).json({error:"Save your TON wallet first."});
 if (!Number.isFinite(amount) || amount<MIN || amount>user.balance)
  return res.status(400).json({error:"Invalid amount or insufficient balance."});

 const pending=db.prepare(
  "SELECT COALESCE(SUM(amount),0) AS total FROM withdrawals WHERE user_id=? AND status='pending'"
 ).get(req.uid).total;

 if (amount>user.balance-pending)
  return res.status(400).json({error:"Insufficient available balance."});

 db.transaction(() => {
  db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount,req.uid);
  db.prepare("INSERT INTO withdrawals(user_id,amount,wallet,method) VALUES(?,?,?,?)")
   .run(req.uid,amount,user.wallet,method);
  db.prepare("INSERT INTO transactions(user_id,amount,note) VALUES(?,?,?)")
   .run(req.uid,-amount,"Withdrawal request");
 })();

 res.json({success:true,message:"Withdrawal submitted."});
});

// ADMIN DASHBOARD
app.get("/api/admin",auth,admin,(req,res) => {
 res.json({
  users:db.prepare("SELECT * FROM users ORDER BY id DESC").all(),
  tasks:db.prepare("SELECT * FROM tasks").all(),
  channels:db.prepare("SELECT * FROM channels").all(),
  submissions:db.prepare("SELECT * FROM submissions ORDER BY id DESC").all(),
  withdrawals:db.prepare("SELECT * FROM withdrawals ORDER BY id DESC").all()
 });
});

// ADD TASK
app.post("/api/admin/task",auth,admin,(req,res) => {
 const title=String(req.body.title || "").trim();
 const reward=Number(req.body.reward);
 const link=String(req.body.link || "");

 if (!title || !Number.isFinite(reward) || reward<=0)
  return res.status(400).json({error:"Invalid task."});

 db.prepare("INSERT INTO tasks(title,reward,link) VALUES(?,?,?)")
  .run(title,reward,link);

 res.json({success:true});
});

// ADD CHANNEL
app.post("/api/admin/channel",auth,admin,(req,res) => {
 const username=String(req.body.username || "").trim();

 if (!/^@[A-Za-z0-9_]{5,}$/.test(username))
  return res.status(400).json({error:"Invalid channel username."});

 db.prepare("INSERT INTO channels(username) VALUES(?)").run(username);
 res.json({success:true});
});

// APPROVE OR REJECT TASK
app.post("/api/admin/submission",auth,admin,(req,res) => {
 const id=Number(req.body.id);
 const action=req.body.action;

 const sub=db.prepare("SELECT * FROM submissions WHERE id=? AND status='pending'")
  .get(id);

 if (!sub) return res.status(404).json({error:"Submission not found."});

 if (action==="approve") {
  const task=db.prepare("SELECT * FROM tasks WHERE id=?").get(sub.task_id);
  if (!task) return res.status(404).json({error:"Task not found."});

  db.transaction(() => {
   db.prepare("UPDATE submissions SET status='approved' WHERE id=?").run(id);
   credit(sub.user_id,task.reward,"Task reward");
  })();
 } else if (action==="reject") {
  db.prepare("UPDATE submissions SET status='rejected' WHERE id=?").run(id);
 } else {
  return res.status(400).json({error:"Invalid action."});
 }

 res.json({success:true});
});

// MANUAL WITHDRAWAL APPROVAL
app.post("/api/admin/withdrawal",auth,admin,(req,res) => {
 const id=Number(req.body.id);
 const action=req.body.action;
 const w=db.prepare("SELECT * FROM withdrawals WHERE id=? AND status='pending'")
  .get(id);

 if (!w) return res.status(404).json({error:"Withdrawal not found."});

 if (action==="approve") {
  db.prepare("UPDATE withdrawals SET status='approved' WHERE id=?").run(id);
 } else if (action==="reject") {
  db.transaction(() => {
   db.prepare("UPDATE withdrawals SET status='rejected' WHERE id=?").run(id);
   credit(w.user_id,w.amount,"Withdrawal refund");
  })();
 } else {
  return res.status(400).json({error:"Invalid action."});
 }

 res.json({success:true});
});

// ADMIN BALANCE CONTROL
app.post("/api/admin/balance",auth,admin,(req,res) => {
 const uid=String(req.body.userId || "");
 const amount=Number(req.body.amount);

 if (!db.prepare("SELECT id FROM users WHERE id=?").get(uid))
  return res.status(404).json({error:"User not found."});

 if (!Number.isFinite(amount) || amount===0)
  return res.status(400).json({error:"Invalid amount."});

 const user=db.prepare("SELECT balance FROM users WHERE id=?").get(uid);
 if (user.balance+amount<0)
  return res.status(400).json({error:"Balance cannot be negative."});

 credit(uid,amount,"Admin balance adjustment");
 res.json({success:true});
});

// REFERRAL REWARD: credited once when referred user qualifies.
// Call this from a verified qualification workflow, not at registration.
function rewardReferral(uid) {
 const user=db.prepare("SELECT referred_by FROM users WHERE id=?").get(uid);
 if (!user || !user.referred_by) return false;

 const referrer=db.prepare("SELECT id FROM users WHERE id=?").get(user.referred_by);
 if (!referrer) return false;

 const prior=db.prepare(
  "SELECT id FROM transactions WHERE user_id=? AND note=?"
 ).get(user.referred_by,"Referral reward for "+uid);

 if (prior) return false;

 credit(user.referred_by,REF,"Referral reward for "+uid);
 return true;
}

// REMOVE CHANNEL
app.delete("/api/admin/channel/:id",auth,admin,(req,res) => {
 db.prepare("DELETE FROM channels WHERE id=?").run(Number(req.params.id));
 res.json({success:true});
});

// HOME PAGE
app.get("/",(req,res) => {
 res.sendFile(path.join(__dirname,"public","index.html"));
});

app.listen(PORT,() => {
 console.log("ROYAL GEM running on port "+PORT);
});
  
