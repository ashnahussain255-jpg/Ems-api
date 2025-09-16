const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const axios = require("axios");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ===================== LOG ENV VARIABLES =====================
console.log("✅ BREVO_API_KEY loaded:", !!process.env.BREVO_API_KEY);
console.log("✅ BREVO_USER loaded:", !!process.env.BREVO_USER);
console.log("✅ MONGO_URI loaded:", !!process.env.MONGO_URI);

// ===================== Schemas =====================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  fullname: { type: String, default: "" },
  phone: { type: String, default: "" },
  cnic: { type: String, default: "" },
  profileImage: { type: String, default: "" },
  otp: String,
  otpExpiry: Date,
  resetToken: String,
  resetTokenExpiry: Date,
});

const User = mongoose.model("User", userSchema);

// ===================== REGISTER =====================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, fullname, phone, cnic } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      fullname: fullname || "",
      phone: phone || "",
      cnic: cnic || "",
    });
    await user.save();

    res.json({ success: true, message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== LOGIN =====================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ error: "Invalid email or password" });

    res.json({ success: true, message: "Login successful" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== REQUEST PASSWORD RESET (OTP) =====================
app.post("/api/auth/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    user.otp = otp;
    user.otpExpiry = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    // Send OTP via Brevo HTTP API
    try {
      const response = await axios.post(
        "https://api.brevo.com/v3/smtp/email",
        {
          sender: { name: "EMS System", email: process.env.BREVO_USER },
          to: [{ email }],
          subject: "🔒 Your OTP for EMS Password Reset",
          htmlContent: `<p>Your OTP is <b>${otp}</b>. Valid for 5 minutes.</p>`,
        },
        {
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            "api-key": process.env.BREVO_API_KEY,
          },
          timeout: 10000, // 10 sec
        }
      );

      console.log("✅ OTP email sent:", response.data);
      res.json({ success: true, message: "OTP sent to your email" });
    } catch (apiErr) {
      console.error("❌ Brevo API error:", apiErr.response?.data || apiErr.message);
      res.status(500).json({ error: "Failed to send OTP email" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== VERIFY OTP =====================
app.post("/api/auth/verify-password-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.otp !== otp || user.otpExpiry < Date.now())
      return res.status(400).json({ error: "Invalid or expired OTP" });

    const resetToken = Math.random().toString(36).substring(2, 15);
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    res.json({ success: true, message: "OTP verified", resetToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== RESET PASSWORD =====================
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, resetToken, newPassword } = req.body;
    if (!email || !resetToken || !newPassword)
      return res.status(400).json({ error: "Email, token and password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.resetToken !== resetToken || user.resetTokenExpiry < Date.now())
      return res.status(400).json({ error: "Invalid or expired reset token" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== GET USER PROFILE =====================
app.get("/api/user/profile", async (req, res) => {
  try {
    const email = req.query.email;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({
      success: true,
      data: {
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        cnic: user.cnic,
        profileImage: user.profileImage || "",
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== UPDATE PROFILE IMAGE =====================
app.post("/api/user/update-profile-image", async (req, res) => {
  try {
    const { email, profileImage } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    user.profileImage = profileImage;
    await user.save();

    res.json({ success: true, message: "Profile image updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== START SERVER =====================
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 10000,
  })
  .then(() => {
    console.log("✅ MongoDB Connected");
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB Connection Error:", err.message);
  });
