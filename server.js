const express = require("express");
const { PrismaClient } = require("@prisma/client");

const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();


const PORT = 8000;

const prisma = new PrismaClient();

app.use(express.json());

// 新規ユーザー登録API
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      username,
      email,
      password: hashedPassword,
    },
  });
  return res.json({ user });
});

// ログインAPI
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    return res.json({ error: "No user found" });
  }

  const passwordValid = await bcrypt.compare(password, user.password);

  if (!passwordValid) {
    return res.json({ error: "Invalid password" });
  }

  const token = jwt.sign({ id: user.id, email: user }, process.env.SECRET_KEY, {
    expiresIn: "1h",
  });

  return res.json({ token });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
