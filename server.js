// ===================== IMPORTS =====================
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();
const http = require("http");
const { Server } = require("socket.io");
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const axios = require("axios");

// ===================== APP + SERVER =====================
const app = express();
const server = http.createServer(app);

// ===================== MIDDLEWARE =====================
app.use(express.json());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

// ===================== SOCKET.IO =====================
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});
io.on("connection", (socket) => {
    console.log("User connected:", socket.id);

 socket.on("askAI", async (data) => {
    const userQuestion = data.question;
    const email = data.email;

    console.log("📩 Query From: " + email);
    console.log("🧠 AI Asked → ", userQuestion);

    try {
        const response = await axios.post(
            "https://api.openai.com/v1/chat/completions",
            {
                model: "gpt-4o-mini",
                messages: [
                    { role: "system", content: "Reply only in plain text. Do not include HTML or Markdown." },
                    { role: "user", content: userQuestion }
                ]
            },
            {
                headers: {
                    "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
                    "Content-Type": "application/json"
                }
            }
        );

        // Correctly get AI's reply
        const aiReply = response.data.choices[0].message.content;

        const sanitizeHtml = require("sanitize-html");
        const aiReplyClean = sanitizeHtml(aiReply, { allowedTags: [], allowedAttributes: {} });

        socket.emit("aiResponse", { reply: aiReplyClean });

    } catch (error) {
   console.log("🔴 AI ERROR:", error.response?.data || error.message);
        console.log("📩 Query From: " + email);
console.log("🧠 AI Asked → ", userQuestion);
        socket.emit("aiResponse", { reply: "AI failed to respond!" });
    }
});
});

io.on("connection", (socket) => {
    console.log("New client connected:", socket.id);
    // Socket room join for device updates
socket.on("joinDevices", ({ userEmail }) => {
    if (userEmail) {
        socket.join(`user_${userEmail}`)
        console.log(`Socket ${socket.id} joined device room user_${userEmail}`);
    }
});
    // Optimization screen room join
   socket.on("join_opt", (data) => {
  const userEmail = data.userEmail;
  if (userEmail) {
    socket.join(`user_${userEmail}_opt`);
    console.log(`User joined optimization room: user_${userEmail}_opt`);
  }
});

    socket.on("join", ({ userEmail }) => {
        if (userEmail) {
            socket.join(`user_${userEmail}_alerts`);
            console.log(`Socket ${socket.id} joined room user_${userEmail}_alerts`);
        }
    });

    socket.on("joinOpt", ({ userEmail }) => {
        if (userEmail) {
            socket.join(`user_${userEmail}_opt`);
            console.log(`Socket ${socket.id} joined room user_${userEmail}_opt`);
        }
    });

    socket.on("disconnect", () => console.log("Client disconnected:", socket.id));
});


// ===================== ALERT MODEL =====================
const alertSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    type: { type: String, required: true },  // Example: voltageover, hightemperature
    value: Number,
    message: String,
    timestamp: { type: Date, default: Date.now }
});
const Alert = mongoose.models.Alert || mongoose.model("Alert", alertSchema);

// ===================== ALERT ROUTES =====================
const router = express.Router();

// Add new alert
router.post("/api/alerts/new", async (req, res) => {
    try {
        const { userEmail, type, value, message } = req.body;
        if (!userEmail || !type) return res.status(400).json({ error: "userEmail and type required" });

        const newAlert = new Alert({ userEmail, type, value, message });
        await newAlert.save();

        // Emit via socket.io
        io.to(`user_${userEmail}_alerts`).emit("newAlert", {
            type,
            value,
            message,
            timestamp: newAlert.timestamp
        });

        res.json({ success: true, alert: newAlert });
    } catch (err) {
        console.error("❌ Alert creation error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get latest alert
router.get("/api/alerts/latest_alert", async (req, res) => {
    try {
        const { userEmail } = req.query;
        if (!userEmail) return res.status(400).json({ error: "userEmail required" });

        const latestAlert = await Alert.findOne({ userEmail }).sort({ timestamp: -1 });
        res.json({ success: true, alert: latestAlert || null });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get alert history
router.get("/api/alerts/history", async (req, res) => {
    try {
        const { userEmail } = req.query;
        if (!userEmail) return res.status(400).json({ error: "userEmail required" });

        const alerts = await Alert.find({ userEmail }).sort({ timestamp: -1 }).limit(100);
        res.json({ success: true, alerts });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// ===================== USE ROUTES =====================
app.use(router);
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


// ===================== LOG ENV VARIABLES =====================
console.log("✅ BREVO_API_KEY loaded:", !!process.env.BREVO_API_KEY);
console.log("✅ BREVO_USER loaded:", !!process.env.BREVO_USER);
console.log("✅ MONGO_URI loaded:", !!process.env.MONGO_URI);
console.log("✅ BASE_URL loaded:", !!process.env.BASE_URL);
console.log("✅ OPENAI_API_KEY loaded:", !!process.env.OPENAI_API_KEY);


// ===================== USER SCHEMA =====================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  fullname: { type: String, default: "" },
  phone: { type: String, default: "" },
  cnic: { type: String, default: "" },
    hardwareIds: { type: String, default: "" },
  profileImage: { type: String, default: "" },
  otp: String,

  otpExpiry: Date,
  resetToken: String,
  resetTokenExpiry: Date,
   emailVerified: { type: Boolean, default: false },   // ✅ new
  verificationToken: { type: String },   
});
const User = mongoose.model("User", userSchema);
// ===================== ADMIN SCHEMA =====================
const adminSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: String
});

const Admin = mongoose.model("Admin", adminSchema);

// ===================== ADMIN REGISTER =====================
app.post("/api/admin/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const existing = await Admin.findOne({ email });
    if (existing) {
      return res.status(400).json({ success: false, error: "Admin already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = new Admin({ email, password: hashedPassword, name });
    await admin.save();

    res.json({ success: true, message: "Admin registered successfully" });
  } catch (err) {
    console.error("❌ Admin Register Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});
// ===================== ADMIN LOGIN =====================
app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(400).json({ success: false, error: "Invalid admin credentials" });
    }

    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      return res.status(400).json({ success: false, error: "Invalid admin credentials" });
    }

    res.json({
      success: true,
      message: "Admin login successful",
      admin: { name: admin.name, email: admin.email }
    });
  } catch (err) {
    console.error("❌ Admin Login Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});
// ===================== HISTORY SCHEMAS =====================
const secondSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const minuteSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const hourSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const daySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now },
});
const monthSchema = new mongoose.Schema({
  userId: { type: String, required: true },
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
// ===================== REGISTER (with Email Verification) =====================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, fullname, phone, cnic,hardwareIds } = req.body;

    if (!email || !password)
      return res.status(400).json({ success: false, error: "Email and password required" });

    // ✅ Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      if (existingUser.emailVerified) {
        return res.status(400).json({ success: false, error: "User already exists" });
      } else {
        return res.status(400).json({ success: false, error: "User registered but not verified. Please check your email." });
      }
    }

    // ✅ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Generate token for verification
    const verificationToken = Math.random().toString(36).substring(2, 15);

    // ✅ Save new user
    const user = new User({
      email,
      password: hashedPassword,
      fullname,
      phone,
      cnic,
      hardwareIds,
      verificationToken,
      emailVerified: false,
    });
    await user.save();

    // ✅ Create user entry in Firebase
    await admin.database().ref("users/" + user._id.toString()).set({
      profile: { fullname, email, phone, cnic },
      devices: {}
    });

    // ✅ Send verification email (Brevo)
    const verifyLink = `${process.env.BASE_URL}/api/auth/verify-email?token=${verificationToken}`;
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: { name: "EMS System", email: process.env.BREVO_USER },
        to: [{ email }],
        subject: "📧 Verify your EMS Email",
        htmlContent: `
          <h3>Welcome to EMS System</h3>
          <p>Hello ${fullname || "User"},</p>
          <p>Please verify your email to activate your account:</p>
          <a href="${verifyLink}" target="_blank" 
             style="padding:10px 15px; background:#4CAF50; color:white; text-decoration:none; border-radius:5px;">
             Verify Email
          </a>
          <p>If you didn’t register, ignore this email.</p>
        `
      },
      {
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          "api-key": process.env.BREVO_API_KEY
        }
      }
    );

    res.json({ success: true, message: "✅ User registered! Check your email for verification link." });

  } catch (err) {
    console.error("❌ Register Error:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});


// ===================== EMAIL VERIFY =====================
app.get("/api/auth/verify-email", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).send("<h3>❌ Invalid verification link.</h3>");

    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.status(400).send("<h3>❌ Invalid or expired token.</h3>");

    user.emailVerified = true;
    user.verificationToken = null;
    await user.save();

    res.send(`
      <h2>✅ Email Verified Successfully!</h2>
      <p>You can now log in to your EMS App.</p>
    `);
  } catch (err) {
    console.error("❌ Email Verify Error:", err.message);
    res.status(500).send("Internal server error");
  }
});


// ===================== LOGIN =====================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ success: false, error: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ success: false, error: "Invalid email or password" });

    // ✅ If not verified
    if (!user.emailVerified)
      return res.status(403).json({
        success: false,
        error: "Please verify your email before logging in."
      });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ success: false, error: "Invalid email or password" });

    res.json({
      success: true,
      message: "✅ Login successful",
      user: {
        userId: user._id,
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

    let profileImageUrl = "";
    if (user.profileImage && user.profileImage.length > 0) {
      profileImageUrl = `data:image/jpeg;base64,${user.profileImage}`;
    }

    res.json({
      success: true,
      data: {
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        cnic: user.cnic,
        profileImageUrl, // ✅ ye Glide me load ho jaayega
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
// ===================== ESP32 DATA ROUTES (SAFE JSON PARSER) =====================
app.post("/api/data", async (req, res) => {
  try {
    const { userId, voltage, current } = req.body; // req.body already object hai
    if (!userId || voltage == null || current == null)
      return res.status(400).json({ error: "Missing userId or voltage/current" });

    await new Second({ userId, voltage, current }).save();
    console.log(`✅ Data received from ESP32: ${JSON.stringify(req.body)}`);

    res.json({ message: "Data stored (second level)", data: req.body });
  } catch (err) {
    console.error("❌ /api/data Error:", err.message, req.body);
    res.status(400).json({ error: "Invalid JSON received", details: err.message });
  }
});

app.get("/api/monthlyAvg", async (req, res) => {
  try {
    const userEmail = req.query.email; // frontend se email pass hoga
    if (!userEmail) return res.status(400).json({ error: "email required" });

    // User find by email
    const user = await User.findOne({ email: userEmail });
    if (!user) return res.status(404).json({ error: "User not found" });

    // hardwareIds array
    const hardwareIds = Array.isArray(user.hardwareIds) ? user.hardwareIds : [user.hardwareIds];

    // Month collection me data fetch karo
    const data = await Month.find({ hardwareid: { $in: hardwareIds } }).sort({ month: 1});

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
// ===================== USER HISTORY API =====================
app.get("/api/history/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const data = await Second.find({ userId }).sort({ timestamp: -1 }); // latest first
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ===================== AGGREGATION FUNCTIONS =====================
// ===================== AGGREGATION FUNCTIONS =====================

// Seconds → Minutes
const aggregateSecondsToMinutes = async (userId) => {
  const seconds = await Second.find({ userId }).sort({ timestamp: 1 });
  if (!seconds.length) return;

  const grouped = {};
  seconds.forEach(s => {
    const minuteTimestamp = new Date(s.timestamp);
    minuteTimestamp.setSeconds(0, 0); // round to minute start
    const key = minuteTimestamp.getTime();
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(s);
  });

  for (const key in grouped) {
    const arr = grouped[key];
    const timestamp = new Date(parseInt(key));
    const avgVoltage = arr.reduce((a, b) => a + b.voltage, 0) / arr.length;
    const avgCurrent = arr.reduce((a, b) => a + b.current, 0) / arr.length;

    await new Minute({ userId, voltage: avgVoltage, current: avgCurrent, timestamp }).save();

    // Delete aggregated seconds
    await Second.deleteMany({ _id: { $in: arr.map(d => d._id) } });
  }
};

// Minutes → Hours
const aggregateMinutesToHours = async (userId) => {
  const minutes = await Minute.find({ userId }).sort({ timestamp: 1 });
  if (!minutes.length) return;

  const grouped = {};
  minutes.forEach(m => {
    const hourTimestamp = new Date(m.timestamp);
    hourTimestamp.setMinutes(0, 0, 0); // round to hour start
    const key = hourTimestamp.getTime();
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(m);
  });

  for (const key in grouped) {
    const arr = grouped[key];
    const timestamp = new Date(parseInt(key));
    const avgVoltage = arr.reduce((a, b) => a + b.voltage, 0) / arr.length;
    const avgCurrent = arr.reduce((a, b) => a + b.current, 0) / arr.length;

    await new Hour({ userId, voltage: avgVoltage, current: avgCurrent, timestamp }).save();

    // Delete aggregated minutes
    await Minute.deleteMany({ _id: { $in: arr.map(d => d._id) } });
  }
};

// Hours → Days
const aggregateHoursToDays = async (userId) => {
  const hours = await Hour.find({ userId }).sort({ timestamp: 1 });
  if (!hours.length) return;

  const grouped = {};
  hours.forEach(h => {
    const dayTimestamp = new Date(h.timestamp);
    dayTimestamp.setHours(0, 0, 0, 0); // round to day start
    const key = dayTimestamp.getTime();
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(h);
  });

  for (const key in grouped) {
    const arr = grouped[key];
    const timestamp = new Date(parseInt(key));
    const avgVoltage = arr.reduce((a, b) => a + b.voltage, 0) / arr.length;
    const avgCurrent = arr.reduce((a, b) => a + b.current, 0) / arr.length;

    await new Day({ userId, voltage: avgVoltage, current: avgCurrent, timestamp }).save();

    // Delete aggregated hours
    await Hour.deleteMany({ _id: { $in: arr.map(d => d._id) } });
  }
};

// Days → Months
const aggregateDaysToMonths = async (userId) => {
  const days = await Day.find({ userId }).sort({ timestamp: 1 });
  if (!days.length) return;

  const grouped = {};
  days.forEach(d => {
    const monthKey = `${d.timestamp.getFullYear()}-${d.timestamp.getMonth() + 1}`;
    if (!grouped[monthKey]) grouped[monthKey] = [];
    grouped[monthKey].push(d);
  });

  for (const key in grouped) {
    const arr = grouped[key];
    const month = (arr[0].timestamp.getMonth() + 1).toString();
    const year = arr[0].timestamp.getFullYear();
    const avgVoltage = arr.reduce((a, b) => a + b.voltage, 0) / arr.length;
    const avgCurrent = arr.reduce((a, b) => a + b.current, 0) / arr.length;

    await new Month({
      month,
      year,
      avgVoltage: avgVoltage.toFixed(2),
      avgCurrent: avgCurrent.toExponential(5),
      hardwareid: userId,
    }).save();

    // Delete aggregated days
    await Day.deleteMany({ _id: { $in: arr.map(d => d._id) } });
  }
};

// ===================== SCHEDULE =====================
 const cron = require("node-cron");

// Cron schedule: every minute at 0 second
cron.schedule("0 * * * * *", async () => {
  try {
    const users = await User.find();

    await Promise.all(users.map(async (user) => {
      const userId = user._id.toString();
      await aggregateSecondsToMinutes(userId);
      await aggregateMinutesToHours(userId);
      await aggregateHoursToDays(userId);
      await aggregateDaysToMonths(userId);
    }));

    console.log("✅ Aggregation completed for all users");
  } catch (err) {
    console.error("❌ Aggregation Error:", err.message);
  }
});
// ✅ Every minute check (not every second)
// ============================================================================
// ✅ FIREBASE → MONGODB LIVE SYNC (ESP32 Data Listener)
// ============================================================================
const dbRef = admin.database().ref("ems_data");

dbRef.on("child_added", (userSnap) => {
  const userId = userSnap.key;
  console.log(`📡 Listening to live data for user: ${userId}`);

  userSnap.child("live").ref.on("value", async (snapshot) => {
    const data = snapshot.val();
    if (!data) return;

    const { voltage, current, timestamp } = data;
    if (voltage == null || current == null) return;

    try {
      await new Second({
        userId,
        voltage,
        current,
        timestamp: timestamp ? new Date(timestamp) : new Date(),
      }).save();

      console.log(`✅ Stored live data for user ${userId}: V=${voltage}, I=${current}`);
    } catch (err) {
      console.error("❌ Mongo insert error:", err.message);
    }
  });
});
const deviceSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  image: { type: String, required: true },
  voltage: Number,
  current: Number,
  isOn: { type: Boolean, default: false },

  latest: {
    units: { type: String, default: "V/A" },
    voltage: Number,
    current: Number
  },

  // datalog array of objects
  datalog: [
    {
      units: { type: String, default: "V/A" },
      voltage: Number,
      timestamp: Date
    }
  ],

  type: String,
  ratedPower: Number,
  latestUnits: { type: String, default: "V/A" },
  latestTimestamp: Date,
});

const Device = mongoose.model("Device", deviceSchema);
// 1️⃣ Get all devices of a user
app.get("/api/devices/:userEmail", async (req, res) => {
    const { userEmail } = req.params;
    try {
        const devices = await Device.find({ userEmail });
        res.json(devices);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2️⃣ Get single device by id
app.get("/api/device/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const device = await Device.findOne({ id });
        if (!device) return res.status(404).json({ error: "Device not found" });
        res.json(device);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3️⃣ Add new device
 app.post("/api/device/new", async (req, res) => {
    const { userEmail, id, name, image, voltage, current } = req.body;
    if (!userEmail || !id || !name) return res.status(400).json({ error: "userEmail, id, name required" });

    try {
        const existing = await Device.findOne({ id });
        if (existing) return res.status(400).json({ error: "Device already exists" });

        const device = new Device({ userEmail, id, name, image, voltage, current });
        await device.save();
        res.json({ message: "Device added", device });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4️⃣ Delete device
app.delete("/api/device/:id", async (req, res) => {
    const { id } = req.params;
    try {
        await Device.deleteOne({ id });
        res.json({ message: "Device deleted" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5️⃣ Toggle device ON/OFF
app.post("/api/device/:id/toggle", async (req, res) => {
    const { id } = req.params;
    const { isOn } = req.body;
    try {
        const device = await Device.findOne({ id });
        if (!device) return res.status(404).json({ error: "Device not found" });

        device.isOn = isOn;
        await device.save();
        res.json({ message: "Device updated", device });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get("/api/device/:id/status", async (req, res) => {
    try {
        const { id } = req.params;
        const device = await Device.findOne({ id });

        if (!device) return res.status(404).json({ error: "Device not found" });

        res.json({
            id: device.id,
            isOn: device.isOn
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
//// ✅ Safe & Robust Update latest units/voltage/current
app.post("/api/device/:id/latest", async (req, res) => {
  try {
    const { id } = req.params;
    let { deviceId, voltage, current, userEmail } = req.body;

    // Validate required fields
    if (!userEmail || !deviceId) {
      return res.status(400).json({ error: "userEmail and deviceId are required" });
    }

    // Ensure numeric values
    voltage = parseFloat(voltage);
    current = parseFloat(current);
    if (isNaN(voltage) || isNaN(current)) {
      return res.status(400).json({ error: "Voltage and Current must be numeric" });
    }

    // Find device
    const device = await Device.findOne({ id, userEmail });
    if (!device) return res.status(404).json({ error: "Device not found" });

    if (!Array.isArray(device.datalog)) device.datalog = [];

    const latestTimestamp = new Date();

    // Update latest with deviceId + units
    device.latest = {
      deviceId,              // <-- now included
      voltage,
      current,
      units: device.latestUnits || "V/A"
    };
    device.latestTimestamp = latestTimestamp;

    // Push to datalog
    device.datalog.push({
      deviceId,
      voltage,
      current,
      units: device.latestUnits || "V/A",
      timestamp: latestTimestamp
    });
    if (device.datalog.length > 100) device.datalog = device.datalog.slice(-100);

    // Save
    await device.save();

    // Emit real-time update
    const payload = { deviceId, voltage, current, units: device.latest.units, timestamp: latestTimestamp };
    if (io) io.to(`user_${userEmail}`).emit("latestData", payload);

    res.json({ success: true, message: "Latest data updated", latest: payload });
  } catch (err) {
    console.error("❌ /api/device/:id/latest Error:", err);
    if (!res.headersSent) res.status(500).json({ error: "Internal server error", details: err.message });
  }
});
// API to get user profile
app.get('/api/userProfile', async (req, res) => {
    const email = req.query.email;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    res.json({ success: true, data: user });
});

// API to get ON devices with real-time data and datalog
app.get('/api/onDevices', async (req, res) => {
    const userEmail = req.query.userEmail;
    if (!userEmail) 
        return res.status(400).json({ success: false, message: 'UserEmail required' });

    try {
        // Get only ON devices for this user
        const devices = await Device.find({ userEmail, isOn: true });

        // Map devices to include latest data and last 50 datalog entries for graph
        const updatedDevices = devices.map(d => {
            const voltage = d.latest?.voltage || 0;
            const current = d.latest?.current || 0;

            return {
                id: d.id,
                name: d.name,
                type: d.type,
                isOn: d.isOn,
                voltage,
                current,
                ratedPower: d.ratedPower,
                datalog: d.datalog.slice(-50) // last 50 readings for real-time graph
            };
        });

        // Calculate total current & voltage
        const totalVoltage = 220; // assuming mains voltage
        const totalCurrent = updatedDevices.reduce((acc, d) => acc + d.current, 0);

        res.json({
            success: true,
            totalVoltage,
            totalCurrent,
            devices: updatedDevices
        });

    } catch (err) {
        console.error("❌ Error fetching ON devices:", err.message);
        res.status(500).json({ success: false, message: err.message });
    }
});
// ------------------- Optimization Latest Units API -------------------
app.post('/api/device/:id/opt-latest', async (req, res) => {
  try {
    const deviceId = req.params.id;
    const { units, userEmail, timestamp } = req.body;

    if (!units || !userEmail) {
      return res.status(400).json({ error: 'units and userEmail required' });
    }

    // 1️⃣ Update device latestUnits
    const device = await Device.findOne({ id: deviceId, userEmail });
    if (!device) return res.status(404).json({ error: "Device not found" });

    const latestTimestamp = timestamp ? new Date(timestamp) : new Date();
    device.latestUnits = parseFloat(units) || 0;
    device.latestTimestamp = latestTimestamp;
    await device.save();

    // 2️⃣ Emit updated totals to all app clients (real-time)
    await emitUserTotalUnits(userEmail);

    // 3️⃣ Respond with updated device info
    res.json({
      success: true,
      device: {
        deviceId: device.id,
        name: device.name,
        units: device.latestUnits,
        timestamp: latestTimestamp
      }
    });

  } catch (err) {
    console.error("❌ /opt-latest Error:", err.message);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

// ------------------- Function to emit total units and alerts -------------------
async function emitUserTotalUnits(userEmail) {
  const allDevices = await Device.find({ userEmail });
  let totalUnits = 0;
  let highestDevice = null;

  allDevices.forEach(d => {
    const dUnits = parseFloat(d.latestUnits) || 0;
    totalUnits += dUnits;
    if (!highestDevice || dUnits > highestDevice.latestUnits) highestDevice = d;
  });

  const payload = {
    totalUnits,
    mainDevice: highestDevice ? highestDevice.name : "Unknown",
    timestamp: new Date()
  };

  io.to(`user_${userEmail}_opt`).emit("opt-latest-total", payload);
  console.log(`✅ TOTAL EMITTED TO APP (${userEmail}):`, totalUnits);

  // Emit alert if total exceeds threshold
  if (totalUnits >= 200 && highestDevice) {
    const alertMessage = `⚠️ High energy consumption: ${totalUnits} units (mainly due to ${highestDevice.name})`;
    const tips = [
      `Consider turning off ${highestDevice.name} to save energy`,
      "Avoid using multiple high-power devices simultaneously",
      "Unplug unused devices to save standby power"
    ];
    io.to(`user_${userEmail}_opt`).emit("alert", { userEmail, message: alertMessage, tips });
  }
}

// ------------------- Socket Join & Emit Latest Total -------------------
io.on("connection", (socket) => {
  console.log("New client connected:", socket.id);

  socket.on("join_opt", async (data) => {
    const userEmail = data.userEmail;
    if (!userEmail) return;

    socket.join(`user_${userEmail}_opt`);
    console.log(`User joined optimization room: user_${userEmail}_opt`);

    // Emit totals immediately when app joins
    await emitUserTotalUnits(userEmail);
  });
});
const readingSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    deviceId: { type: String, required: true },
    voltage: { type: Number, required: true },
    current: { type: Number, required: true },
 
});

const Reading = mongoose.model("Reading", readingSchema);

app.post("/api/reading", async (req, res) => {
  const { userId, deviceId, voltage, current } = req.body;
  const newReading = new Reading({ userId, deviceId, voltage, current });
  await newReading.save();

  // Emit real-time update
  io.emit("newReading", newReading);

  res.status(201).send({ message: "Reading saved", reading: newReading });
});


const hardwareSchema = new mongoose.Schema({
  name: { type: String, required: true },
  status: { type: Boolean, default: false }, // false = not connected, true = connected
  password: { type: String, required: true },
  data: { type: Number, default: 0 },        // temporary storage for connected hardware
});
const Hardware = mongoose.model('Hardware', hardwareSchema);
// GET all hardware
app.get('/api/hardware/all', async (req, res) => {
  try {
    const hardwareList = await Hardware.find();

    const devices = hardwareList.map(hw => hw.name);

    res.json({ devices });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});
// GET hardware status
app.get('/api/hardware/:name/status', async (req, res) => {
  const name = req.params.name;

  const hw = await Hardware.findOne({ name });

  if (!hw) {
    return res.json({ status: false, data: 0 });
  }

  res.json({
    status: hw.status,
    data: hw.data
  });
});
// Connect hardware
app.post('/api/hardware/connect', async (req, res) => {
  const { name, password } = req.body;
  let hw = await Hardware.findOne({ name });

  if (!hw) {
    hw = new Hardware({ name, password, status: true, data: 0 });
    await hw.save();
    return res.json({ message: 'Hardware connected', status: true });
  }

  if (hw.password !== password) return res.status(401).json({ error: 'Wrong password' });

  hw.status = true;
  await hw.save();
  res.json({ message: 'Hardware connected', status: hw.status });
});

// Update device data (barrier check)
app.post('/api/device/:id/update', async (req, res) => {
  const { hardwareName, value } = req.body; // hardwareName is mandatory
  const hw = await Hardware.findOne({ name: hardwareName });

  if (!hw || !hw.status) {
    // Hardware not connected → block data
    return res.status(400).json({ error: 'Hardware not connected. Data blocked.' });
  }

  // Hardware connected → normal device update
  const device = await Device.findById(req.params.id);
  device.data = value; // example
  await device.save();
  res.json({ message: 'Device data updated', data: device.data });
});

// Fetch alerts (barrier check)
app.get('/api/alerts/:userEmail', async (req, res) => {
  const { hardwareName } = req.query;
  const hw = await Hardware.findOne({ name: hardwareName });

  if (!hw || !hw.status) {
    return res.status(400).json({ error: 'Hardware not connected. Alerts blocked.' });
  }

  const alerts = await Alert.find({ userEmail: req.params.userEmail });
  res.json(alerts);
});
// Update hardware password
app.post('/api/hardware/update-password', async (req, res) => {
  const { name, password } = req.body;
  const hw = await Hardware.findOne({ name });
  if (!hw) return res.status(404).json({ status: false, message: 'Hardware not found' });

  hw.password = password;
  await hw.save();
  res.json({ status: true, message: 'Password updated successfully' });
});
// ===================== CONNECT MONGO + START SERVER =====================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");
    const port = process.env.PORT || 3000;
    server.listen(port, () => console.log(`🚀 Server running on port ${port}`));
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err.message));
