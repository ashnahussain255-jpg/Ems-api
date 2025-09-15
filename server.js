const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
require("dotenv").config();
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ===================== Nodemailer (Brevo) =====================


const transporter = nodemailer.createTransport({
  host: "smtpout.secureserver.net", // GoDaddy SMTP server
  port: 465,                        // SSL port
  secure: true,                     // true for 465, false for 587
  auth: {
    user: "sparksisters@vartas.xyz", // your full GoDaddy email
    pass: "ashna@123",     // your email password
  },
  tls: {
    rejectUnauthorized: false,      // needed for some environments
  },
});

// ===================== Schemas =====================
// ===================== Schemas =====================
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  fullname: { type: String, default: "" }, // add
  phone: { type: String, default: "" },    // add
  cnic: { type: String, default: "" },     // add
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
      profileImage: ""
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
    console.error("Login Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ===================== REQUEST PASSWORD RESET (OTP) =====================
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

   console.log('Generated OTP type:', typeof user.otp, 'value:', user.otp);

    // ✅ Send HTML email with friendly name
    transporter.sendMail({
      from: `"EMS System" <sparksisters@vartas.xyz>`, // Friendly name
      to: email,
      subject: "🔒 Your OTP for EMS Password Reset",
      html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h2>Password Reset Request</h2>
          <p>Hello,</p>
          <p>Your OTP code is: <strong style="font-size: 24px;">${otp}</strong></p>
          <p>This code is valid for 5 minutes.</p>
          <p>If you did not request a password reset, please ignore this email.</p>
          <hr/>
          <p style="font-size: 12px; color: #888;">EMS System</p>
        </div>
      `,
    }, (err, info) => {
      if (err) console.error("❌ Email send error:", err);
      else console.log("✅ Email sent:", info.response);
    });

    res.json({ success: true, message: "OTP sent to your email" });
  } catch (err) {
    console.error("OTP Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ===================== VERIFY OTP =====================
// ===================== VERIFY OTP =====================
app.post("/api/auth/verify-password-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp)
      return res.status(400).json({ error: "Email and OTP required" });

    const user = await User.findOne({ email });
    if (!user || user.otp !== otp || user.otpExpiry < Date.now())
      return res.status(400).json({ error: "Invalid or expired OTP" });

    // ✅ Generate reset token
    const resetToken = Math.random().toString(36).substring(2, 15);

    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 10 * 60 * 1000; // 10 min valid
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    console.log(`✅ OTP verified for ${email}, resetToken: ${resetToken}`);

    res.json({
      success: true,
      resetToken,
      message: "OTP verified successfully"
    });
  } catch (err) {
    console.error("Verify OTP Error:", err.message);
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

    // ✅ check token validity
    if (user.resetToken !== resetToken || user.resetTokenExpiry < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }

    // ✅ update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // ✅ clear reset token
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("Reset Password Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/user/profile', async (req, res) => {
    const email = req.query.email;
    const user = await User.findOne({ email: email });
    if (!user) return res.json({ success: false, message: "User not found" });

    res.json({
        success: true,
        data: {
            fullname: user.fullname,
            email: user.email,
            phone: user.phone,
            cnic: user.cnic,
            profileImage: user.profileImage || ""
        }
    });
});
app.post('/api/user/update-profile-image', async (req, res) => {
    const { email, profileImage } = req.body;

    const user = await User.findOne({ email: email });
    if (!user) return res.json({ success: false, message: "User not found" });

    user.profileImage = profileImage;
    await user.save();

    res.json({ success: true, message: "Profile image updated" });
});
// ===================== Start Server =====================
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000,
})
.then(() => {
  console.log("✅ MongoDB Connected");
  app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 Server running on port ${process.env.PORT || 3000}`);
  });
})
.catch(err => {
  console.error("❌ MongoDB Connection Error:", err.message);
});