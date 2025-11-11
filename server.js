const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const axios = require("axios");
require("dotenv").config();
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
app.use(cors({
  origin: "*", // ✅ allow all origins globally (mobile app, web, IoT)
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// ===================== LOG ENV VARIABLES =====================
console.log("✅ BREVO_API_KEY loaded:", !!process.env.BREVO_API_KEY);
console.log("✅ BREVO_USER loaded:", !!process.env.BREVO_USER);
console.log("✅ MONGO_URI loaded:", !!process.env.MONGO_URI);
console.log("✅ BASE_URL loaded:", !!process.env.BASE_URL);

// ===================== USER SCHEMA =====================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  fullname: { type: String, default: "" },
  phone: { type: String, default: "" },
  cnic: { type: String, default: "" },
    userid: { type: String, default: "" },
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
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  name: { type: String, default: "Admin" }
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
    const { email, password, fullname, phone, cnic,userid } = req.body;

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
      userid,
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
    const userId = req.query.userId; // get userId from request
    if (!userId) return res.status(400).json({ error: "userId required" });

    const data = await Month.find({ userId }).sort({ year: 1, month: 1 });
    res.json(data);
  } catch (err) {
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
async function aggregateSecondsToMinutes(userId) {
  const cutoff = new Date(Date.now() - 60 * 1000);
  const seconds = await Second.find({ timestamp: { $lte: cutoff }, userId });
  if (seconds.length > 0) {
    const avgVoltage = seconds.reduce((a, b) => a + b.voltage, 0) / seconds.length;
    const avgCurrent = seconds.reduce((a, b) => a + b.current, 0) / seconds.length;
    await new Minute({ userId, voltage: avgVoltage, current: avgCurrent }).save();
    await Second.deleteMany({ timestamp: { $lte: cutoff }, userId });
  }
}

async function aggregateMinutesToHours(userId) {
  const cutoff = new Date(Date.now() - 60 * 60 * 1000);
  const minutes = await Minute.find({ timestamp: { $lte: cutoff }, userId });
  if (minutes.length > 0) {
    const avgVoltage = minutes.reduce((a, b) => a + b.voltage, 0) / minutes.length;
    const avgCurrent = minutes.reduce((a, b) => a + b.current, 0) / minutes.length;
    await new Hour({ userId, voltage: avgVoltage, current: avgCurrent }).save();
    await Minute.deleteMany({ timestamp: { $lte: cutoff }, userId });
  }
}

async function aggregateHoursToDays(userId) {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const hours = await Hour.find({ timestamp: { $lte: cutoff }, userId });
  if (hours.length > 0) {
    const avgVoltage = hours.reduce((a, b) => a + b.voltage, 0) / hours.length;
    const avgCurrent = hours.reduce((a, b) => a + b.current, 0) / hours.length;
    await new Day({ userId, voltage: avgVoltage, current: avgCurrent }).save();
    await Hour.deleteMany({ timestamp: { $lte: cutoff }, userId });
  }
}

// ===================== MONTHLY AGGREGATION =====================
async function aggregateDaysToMonths(userId) {
  const now = new Date();
  const cutoff = new Date(now.getFullYear(), now.getMonth(), 0);
  const days = await Day.find({ timestamp: { $lte: cutoff }, userId });
  if (days.length > 0) {
    const avgVoltage = days.reduce((a, b) => a + b.voltage, 0) / days.length;
    const avgCurrent = days.reduce((a, b) => a + b.current, 0) / days.length;

    await Month.updateOne(
      { userId, month: cutoff.getMonth() + 1, year: cutoff.getFullYear() },
      { avgVoltage, avgCurrent },
      { upsert: true }
    );

    await Day.deleteMany({ timestamp: { $lte: cutoff }, userId });
  }
}



// ===================== SCHEDULE =====================
setInterval(async () => {
  const users = await User.find();
  for (const user of users) {
    await aggregateSecondsToMinutes(user._id.toString());
    await aggregateMinutesToHours(user._id.toString());
    await aggregateHoursToDays(user._id.toString());
    await aggregateDaysToMonths(user._id.toString());
  }
}, 60 * 1000);
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
// ===================== CONNECT MONGO + START SERVER =====================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");
    const port = process.env.PORT || 3000;
    app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err.message));
