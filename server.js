const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";

app.use(cors());
app.use(express.json());

// ─── In-memory database (replace with a real DB like MongoDB/PostgreSQL later) ───
const db = {
  users: [
    {
      id: "t1",
      role: "teacher",
      name: "Mr. Teacher",
      username: "teacher",
      passwordHash: bcrypt.hashSync("admin123", 10),
    },
  ],
  students: [],
  tests: [],
  results: [],
};

// ─── Middleware: verify JWT ───────────────────────────────────────────────────
function auth(requiredRole) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "No token provided" });
    const token = header.split(" ")[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (requiredRole && decoded.role !== requiredRole)
        return res.status(403).json({ error: "Forbidden" });
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: "Invalid or expired token" });
    }
  };
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// POST /api/login
app.post("/api/login", (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role)
    return res.status(400).json({ error: "username, password and role required" });

  let user = null;
  if (role === "teacher") {
    user = db.users.find((u) => u.role === "teacher" && u.username === username);
  } else {
    user = db.students.find((s) => s.username === username);
    if (user) user = { ...user, role: "student" };
  }

  if (!user || !bcrypt.compareSync(password, user.passwordHash))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, name: user.name, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
  res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
});

// ─── STUDENTS (teacher only) ──────────────────────────────────────────────────

// GET /api/students
app.get("/api/students", auth("teacher"), (req, res) => {
  const list = db.students.map(({ passwordHash, ...s }) => s);
  res.json(list);
});

// POST /api/students
app.post("/api/students", auth("teacher"), (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password)
    return res.status(400).json({ error: "name, username and password required" });
  if (db.students.find((s) => s.username === username))
    return res.status(409).json({ error: "Username already taken" });

  const student = {
    id: "s" + Date.now(),
    name,
    username,
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: new Date().toISOString(),
  };
  db.students.push(student);
  const { passwordHash, ...safe } = student;
  res.status(201).json(safe);
});

// DELETE /api/students/:id
app.delete("/api/students/:id", auth("teacher"), (req, res) => {
  db.students = db.students.filter((s) => s.id !== req.params.id);
  db.results = db.results.filter((r) => r.studentId !== req.params.id);
  res.json({ ok: true });
});

// ─── TESTS ────────────────────────────────────────────────────────────────────

// GET /api/tests  (teacher sees all, student sees active only)
app.get("/api/tests", auth(), (req, res) => {
  if (req.user.role === "teacher") return res.json(db.tests);
  res.json(db.tests.filter((t) => t.active));
});

// POST /api/tests  (teacher only)
app.post("/api/tests", auth("teacher"), (req, res) => {
  const { title, subject, duration, pass, questions } = req.body;
  if (!title || !subject || !questions?.length)
    return res.status(400).json({ error: "title, subject and questions required" });

  const test = {
    id: "t" + Date.now(),
    title,
    subject,
    duration: duration || 45,
    pass: pass || 50,
    questions,
    active: true,
    createdAt: new Date().toISOString(),
  };
  db.tests.push(test);
  res.status(201).json(test);
});

// PATCH /api/tests/:id  (toggle active, update fields)
app.patch("/api/tests/:id", auth("teacher"), (req, res) => {
  const test = db.tests.find((t) => t.id === req.params.id);
  if (!test) return res.status(404).json({ error: "Test not found" });
  Object.assign(test, req.body);
  res.json(test);
});

// DELETE /api/tests/:id
app.delete("/api/tests/:id", auth("teacher"), (req, res) => {
  db.tests = db.tests.filter((t) => t.id !== req.params.id);
  res.json({ ok: true });
});

// ─── RESULTS ─────────────────────────────────────────────────────────────────

// POST /api/results  (student submits answers)
app.post("/api/results", auth("student"), (req, res) => {
  const { testId, answers } = req.body; // answers: { "0": "A", "1": "C", ... }
  const test = db.tests.find((t) => t.id === testId);
  if (!test) return res.status(404).json({ error: "Test not found" });

  let correct = 0, wrong = 0, skipped = 0;
  test.questions.forEach((q, i) => {
    const a = answers[i];
    if (!a) skipped++;
    else if (a === q.correct) correct++;
    else wrong++;
  });

  const total = test.questions.length;
  const pct = Math.round((correct / total) * 100);
  const grade = pct >= 75 ? "Distinction" : pct >= 60 ? "Credit" : pct >= 50 ? "Pass" : "Fail";

  const result = {
    id: "r" + Date.now(),
    testId,
    testTitle: test.title,
    studentId: req.user.id,
    studentName: req.user.name,
    answers,
    correct,
    wrong,
    skipped,
    total,
    pct,
    grade,
    passed: pct >= test.pass,
    submittedAt: new Date().toISOString(),
  };
  db.results.push(result);
  res.status(201).json(result);
});

// GET /api/results  (teacher sees all; student sees own)
app.get("/api/results", auth(), (req, res) => {
  if (req.user.role === "teacher") return res.json(db.results);
  res.json(db.results.filter((r) => r.studentId === req.user.id));
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`CBT backend running on http://localhost:${PORT}`);
  console.log(`Default teacher login → username: teacher  password: admin123`);
});
