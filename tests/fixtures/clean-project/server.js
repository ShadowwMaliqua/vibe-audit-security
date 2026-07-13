const express = require("express");
const cors = require("cors");
const app = express();

const ALLOWED_ORIGINS = ["https://example.com"];

app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));

app.get("/search", (req, res) => {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = $1", [userId], (err, rows) => res.json(rows));
});

app.listen(3000);
