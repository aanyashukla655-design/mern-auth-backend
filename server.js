import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import User from "./models/User.js";
import auth from "./middleware/auth.js";

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log(" MongoDB Connected "))
  .catch((err) => console.log(err));

// REGISTER
app.post("/api/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser)
    return res.status(400).json({ message: "Email already used" });

  const hashed = await bcrypt.hash(password, 10);

  const user = await User.create({
    name,
    email,
    password: hashed,
    role: role || "user"
  });

  res.json({ message: "Registration successful", user });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({
    message: "Login success",
    token,
    user: { id: user._id, name: user.name, email: user.email, role: user.role }
  });
});

// USER ROUTE (Protected)
app.get("/api/user", auth(), (req, res) => {
  res.json({ message: "User Route Accessed", user: req.user });
});

// ADMIN ROUTE (Protected)
app.get("/api/admin", auth(["admin"]), (req, res) => {
  res.json({ message: "Admin Route Accessed", user: req.user });
});

app.listen(process.env.PORT, () =>
  console.log(` Server running on port ${process.env.PORT} `)
);
