// Intentionally vulnerable fixture used to test vibe-audit's own scanners.
// Every issue in this file is deliberate, do not "fix" it, that would
// break the test suite that asserts these findings are detected.
const express = require("express");
const cors = require("cors");
const app = express();

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

// Wide-open CORS: wildcard origin combined with credentials enabled.
app.use(cors({ origin: "*", credentials: true }));

app.get("/search", (req, res) => {
  const userId = req.query.id;
  // SQL built via string concatenation instead of a parameterized query.
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, rows) => res.json(rows));
});

app.post("/eval", (req, res) => {
  // Never do this: executes arbitrary user input as code.
  const result = eval(req.body.expression);
  res.json({ result });
});

app.listen(3000);
