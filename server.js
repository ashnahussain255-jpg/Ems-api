const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const axios = require("axios");
require("dotenv").config(); // local testing ke liye .env file se
const admin = require("firebase-admin");

// env var se JSON uthao
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("❌ FIREBASE_SERVICE_ACCOUNT env var missing");
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

// Firebase initialize
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://varta-152e4-default-rtdb.firebaseio.com/"
});
const app = express();
app.use(express.json());
app.use(cors());

// ===================== LOG ENV VARIABLES =====================
console.log("✅ BREVO_API_KEY loaded:", !!process.env.BREVO_API_KEY);
console.log("✅ BREVO_USER loaded:", !!process.env.BREVO_USER);
console.log("✅ MONGO_URI loaded:", !!process.env.MONGO_URI);

// ===================== USER SCHEMA =====================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
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

// ===================== HISTORY SCHEMAS =====================
const secondSchema = new mongoose.Schema({
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const minuteSchema = new mongoose.Schema({
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const hourSchema = new mongoose.Schema({
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const daySchema = new mongoose.Schema({
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const monthSchema = new mongoose.Schema({
  month: Number,
  year: Number,
  avgVoltage: Number,
  avgCurrent: Number,
});

const Second = mongoose.model("Second", secondSchema);
const Minute = mongoose.model("Minute", minuteSchema);
const Hour = mongoose.model("Hour", hourSchema);
const Day = mongoose.model("Day", daySchema);
const Month = mongoose.model("Month", monthSchema);

// ===================== TEST ROUTE =====================
app.get("/test", (req, res) => res.send("🚀 EMS API is live!"));

// ===================== AUTH ROUTES =====================
// ===================== REGISTER =====================
// ===================== REGISTER =====================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, fullname, phone, cnic } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Email and password required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      fullname: fullname || "",
      phone: phone || "",
      cnic: cnic || "",
    });
    await user.save();

    // 🔥 Firebase me user node auto create
    await admin.database().ref("users/" + user._id.toString()).set({
      profile: {
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        cnic: user.cnic
      },
      devices: {}
    });

    res.json({ success: true, message: "User registered successfully", userId: user._id });
  } catch (err) {
    console.error("❌ Register Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ===================== LOGIN =====================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, error: "Invalid email or password" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ success: false, error: "Invalid email or password" });
    }

    res.json({
      success: true,
      message: "Login successful",
      user: {
        userId: user._id,   // 🔥 important
        fullname: user.fullname,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (err) {
    console.error("❌ Login Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ===================== REQUEST PASSWORD RESET (OTP) =====================
app.post("/api/auth/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    user.otp = otp;
    user.otpExpiry = Date.now() + 5 * 60 * 1000; // 5 min
    await user.save();

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
          timeout: 10000,
        }
      );

      console.log("✅ OTP Email Sent:", response.data);
      res.json({ success: true, message: "OTP sent to your email" });
    } catch (apiErr) {
      console.error("❌ Brevo API Error:", apiErr.response?.data || apiErr.message);
      res.status(500).json({ success: false, error: "Failed to send OTP email" });
    }
  } catch (err) {
    console.error("❌ OTP Request Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ===================== VERIFY OTP =====================
app.post("/api/auth/verify-password-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, error: "Email and OTP required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    if (user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ success: false, error: "Invalid or expired OTP" });
    }

    const resetToken = Math.random().toString(36).substring(2, 15);
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 min
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    res.json({ success: true, message: "OTP verified", resetToken });
  } catch (err) {
    console.error("❌ OTP Verify Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ===================== RESET PASSWORD =====================
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, resetToken, newPassword } = req.body;

    if (!email || !resetToken || !newPassword) {
      return res.status(400).json({ success: false, error: "Email, token and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    if (user.resetToken !== resetToken || user.resetTokenExpiry < Date.now()) {
      return res.status(400).json({ success: false, error: "Invalid or expired reset token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("❌ Reset Password Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ===================== GET USER PROFILE =====================
app.get("/api/user/profile", async (req, res) => {
  try {
    const email = req.query.email;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, error: "User not found" });

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
    console.error("❌ Get Profile Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

// ===================== UPDATE PROFILE IMAGE =====================
app.post("/api/user/update-profile-image", async (req, res) => {
  try {
    const { email, profileImage } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    user.profileImage = profileImage;
    await user.save();

    res.json({ success: true, message: "Profile image updated" });
  } catch (err) {
    console.error("❌ Update Profile Image Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});
// ===================== ESP32 DATA ROUTES =====================
app.post("/api/data", async (req, res) => {
  try {
    const { voltage, current } = req.body;
    if (voltage == null || current == null)
      return res.status(400).json({ error: "Missing voltage/current" });

    await new Second({ voltage, current }).save();
    res.json({ message: "Data stored (second level)" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/monthlyAvg", async (req, res) => {
  try {
    const data = await Month.find().sort({ year: 1, month: 1 });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== AGGREGATION FUNCTIONS =====================
async function aggregateSecondsToMinutes() {
  const cutoff = new Date(Date.now() - 60 * 1000);
  const seconds = await Second.find({ timestamp: { $lte: cutoff } });
  if (seconds.length > 0) {
    const avgVoltage = seconds.reduce((a, b) => a + b.voltage, 0) / seconds.length;
    const avgCurrent = seconds.reduce((a, b) => a + b.current, 0) / seconds.length;
    await new Minute({ voltage: avgVoltage, current: avgCurrent }).save();
    await Second.deleteMany({ timestamp: { $lte: cutoff } });
  }
}

async function aggregateMinutesToHours() {
  const cutoff = new Date(Date.now() - 60 * 60 * 1000);
  const minutes = await Minute.find({ timestamp: { $lte: cutoff } });
  if (minutes.length > 0) {
    const avgVoltage = minutes.reduce((a, b) => a + b.voltage, 0) / minutes.length;
    const avgCurrent = minutes.reduce((a, b) => a + b.current, 0) / minutes.length;
    await new Hour({ voltage: avgVoltage, current: avgCurrent }).save();
    await Minute.deleteMany({ timestamp: { $lte: cutoff } });
  }
}

async function aggregateHoursToDays() {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const hours = await Hour.find({ timestamp: { $lte: cutoff } });
  if (hours.length > 0) {
    const avgVoltage = hours.reduce((a, b) => a + b.voltage, 0) / hours.length;
    const avgCurrent = hours.reduce((a, b) => a + b.current, 0) / hours.length;
    await new Day({ voltage: avgVoltage, current: avgCurrent }).save();
    await Hour.deleteMany({ timestamp: { $lte: cutoff } });
  }
}

async function aggregateDaysToMonths() {
  const now = new Date();
  const cutoff = new Date(now.getFullYear(), now.getMonth(), 0);
  const days = await Day.find({ timestamp: { $lte: cutoff } });
  if (days.length > 0) {
    const avgVoltage = days.reduce((a, b) => a + b.voltage, 0) / days.length;
    const avgCurrent = days.reduce((a, b) => a + b.current, 0) / days.length;

    await Month.updateOne(
      { month: cutoff.getMonth() + 1, year: cutoff.getFullYear() },
      { avgVoltage, avgCurrent },
      { upsert: true }
    );
    await Day.deleteMany({ timestamp: { $lte: cutoff } });
  }
}

// ===================== SCHEDULE =====================
setInterval(aggregateSecondsToMinutes, 60 * 1000);
setInterval(aggregateMinutesToHours, 60 * 60 * 1000);
setInterval(aggregateHoursToDays, 24 * 60 * 60 * 1000);
setInterval(aggregateDaysToMonths, 24 * 60 * 60  * 1000);

// ===================== CONNECT MONGO + START SERVER =====================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err.message));
