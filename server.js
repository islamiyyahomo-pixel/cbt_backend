const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";

app.use(cors());
app.use(express.json({ limit: "5mb" }));

const db = {
  users: [{ id:"t1",role:"teacher",name:"Mr. Teacher",username:"teacher",passwordHash:bcrypt.hashSync("admin123",10) }],
  students: [], tests: [], results: []
};

function auth(requiredRole) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "No token provided" });
    const token = header.split(" ")[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (requiredRole && decoded.role !== requiredRole) return res.status(403).json({ error: "Forbidden" });
      req.user = decoded; next();
    } catch { res.status(401).json({ error: "Invalid or expired token" }); }
  };
}

// LOGIN
app.post("/api/login", (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: "username, password and role required" });
  let user = role === "teacher"
    ? db.users.find(u => u.role === "teacher" && u.username === username)
    : db.students.find(s => s.username === username);
  if (user && role === "student") user = { ...user, role: "student" };
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id:user.id, name:user.name, username:user.username, role:user.role }, JWT_SECRET, { expiresIn:"8h" });
  res.json({ token, user: { id:user.id, name:user.name, role:user.role } });
});

// STUDENTS
app.get("/api/students", auth("teacher"), (req, res) => res.json(db.students.map(({ passwordHash, ...s }) => s)));

app.post("/api/students", auth("teacher"), (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: "name, username and password required" });
  if (db.students.find(s => s.username === username)) return res.status(409).json({ error: "Username already taken" });
  const student = { id:"s"+Date.now(), name, username, passwordHash:bcrypt.hashSync(password,10), createdAt:new Date().toISOString() };
  db.students.push(student);
  const { passwordHash, ...safe } = student;
  res.status(201).json(safe);
});

app.post("/api/students/bulk", auth("teacher"), (req, res) => {
  const { students } = req.body;
  if (!students || !students.length) return res.status(400).json({ error: "students array required" });
  let added = 0, skipped = [];
  students.forEach(s => {
    if (!s.name || !s.username || !s.password) { skipped.push(s.username || "?"); return; }
    if (db.students.find(x => x.username === s.username)) { skipped.push(s.username); return; }
    db.students.push({ id:"s"+Date.now()+Math.random(), name:s.name, username:s.username, passwordHash:bcrypt.hashSync(s.password,10), createdAt:new Date().toISOString() });
    added++;
  });
  res.status(201).json({ added, skipped });
});

app.patch("/api/students/:id", auth("teacher"), (req, res) => {
  const s = db.students.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Student not found" });
  if (req.body.name) s.name = req.body.name;
  if (req.body.password) s.passwordHash = bcrypt.hashSync(req.body.password, 10);
  const { passwordHash, ...safe } = s;
  res.json(safe);
});

app.delete("/api/students/:id", auth("teacher"), (req, res) => {
  db.students = db.students.filter(s => s.id !== req.params.id);
  db.results = db.results.filter(r => r.studentId !== req.params.id);
  res.json({ ok: true });
});

// TESTS
app.get("/api/tests", auth(), (req, res) => {
  const now = new Date();
  if (req.user.role === "teacher") return res.json(db.tests);
  res.json(db.tests.filter(t => {
    if (!t.active) return false;
    if (t.startDate && new Date(t.startDate) > now) return false;
    if (t.endDate && new Date(t.endDate) < now) return false;
    return true;
  }));
});

app.post("/api/tests", auth("teacher"), (req, res) => {
  const { title, subject, duration, pass, questions, shuffleQuestions, oneAttemptOnly, startDate, endDate, timeLimitPerQuestion, fullscreenRequired } = req.body;
  if (!title || !subject || !questions?.length) return res.status(400).json({ error: "title, subject and questions required" });
  const test = {
    id:"t"+Date.now(), title, subject, duration:duration||45, pass:pass||50, questions,
    shuffleQuestions:!!shuffleQuestions, oneAttemptOnly:!!oneAttemptOnly,
    fullscreenRequired:!!fullscreenRequired, timeLimitPerQuestion:timeLimitPerQuestion||null,
    startDate:startDate||null, endDate:endDate||null, active:true, createdAt:new Date().toISOString()
  };
  db.tests.push(test);
  res.status(201).json(test);
});

app.patch("/api/tests/:id", auth("teacher"), (req, res) => {
  const test = db.tests.find(t => t.id === req.params.id);
  if (!test) return res.status(404).json({ error: "Test not found" });
  Object.assign(test, req.body);
  res.json(test);
});

app.delete("/api/tests/:id", auth("teacher"), (req, res) => {
  db.tests = db.tests.filter(t => t.id !== req.params.id);
  res.json({ ok: true });
});

// RESULTS
app.post("/api/results", auth("student"), (req, res) => {
  const { testId, answers, tabSwitches, flaggedQuestions } = req.body;
  const test = db.tests.find(t => t.id === testId);
  if (!test) return res.status(404).json({ error: "Test not found" });
  if (test.oneAttemptOnly) {
    const existing = db.results.find(r => r.testId === testId && r.studentId === req.user.id);
    if (existing) return res.status(403).json({ error: "Only one attempt allowed for this test." });
  }
  let correct=0, wrong=0, skipped=0;
  test.questions.forEach((q,i) => { const a=answers[i]; if(!a) skipped++; else if(a===q.correct) correct++; else wrong++; });
  const total=test.questions.length, pct=Math.round((correct/total)*100);
  const grade = pct>=75?"Distinction":pct>=60?"Credit":pct>=50?"Pass":"Fail";
  const result = {
    id:"r"+Date.now(), testId, testTitle:test.title,
    studentId:req.user.id, studentName:req.user.name,
    answers, correct, wrong, skipped, total, pct, grade,
    passed:pct>=test.pass, tabSwitches:tabSwitches||0,
    flaggedQuestions:flaggedQuestions||[], submittedAt:new Date().toISOString()
  };
  db.results.push(result);
  res.status(201).json(result);
});

app.get("/api/results", auth(), (req, res) => {
  if (req.user.role === "teacher") return res.json(db.results);
  res.json(db.results.filter(r => r.studentId === req.user.id));
});

// STATS
app.get("/api/stats", auth("teacher"), (req, res) => {
  const tests = db.tests.map(t => {
    const attempts = db.results.filter(r => r.testId === t.id);
    const avg = attempts.length ? Math.round(attempts.reduce((a,r)=>a+r.pct,0)/attempts.length) : 0;
    const passed = attempts.filter(r => r.passed).length;
    const gradeBreakdown = { Distinction:0, Credit:0, Pass:0, Fail:0 };
    attempts.forEach(r => { if(gradeBreakdown[r.grade]!==undefined) gradeBreakdown[r.grade]++; });
    const questionStats = t.questions.map((q,i) => {
      const answered = attempts.filter(r => r.answers && r.answers[i]);
      const correctCount = answered.filter(r => r.answers[i]===q.correct).length;
      return { question:q.question.substring(0,60), correctRate: answered.length ? Math.round((correctCount/answered.length)*100) : 0 };
    });
    return { testId:t.id, title:t.title, attempts:attempts.length, avg, passed, failed:attempts.length-passed, gradeBreakdown, questionStats };
  });
  const totalAttempts = db.results.length;
  const overallAvg = totalAttempts ? Math.round(db.results.reduce((a,r)=>a+r.pct,0)/totalAttempts) : 0;
  res.json({ tests, overall:{ totalStudents:db.students.length, totalAttempts, overallAvg, totalTests:db.tests.length } });
});

app.get("/api/results/:id/report", auth("teacher"), (req, res) => {
  const result = db.results.find(r => r.id === req.params.id);
  if (!result) return res.status(404).json({ error: "Result not found" });
  const test = db.tests.find(t => t.id === result.testId);
  res.json({ result, test: test || { title:result.testTitle, questions:[] } });
});

app.get("/api/health", (req, res) => res.json({ status:"ok", uptime:process.uptime() }));

app.listen(PORT, () => {
  console.log(`CBT backend running on http://localhost:${PORT}`);
  console.log(`Default teacher login → username: teacher  password: admin123`);
});
