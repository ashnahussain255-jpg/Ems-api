const functions = require("firebase-functions");
const nodemailer = require("nodemailer");

// Gmail SMTP setup (better: use App Password, not real password)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "your-email@gmail.com",
    pass: "your-app-password", // Gmail App Password
  },
});

exports.sendOtp = functions.https.onCall(async (data, context) => {
  const email = data.email;
  if (!email) {
    throw new functions.https.HttpsError("invalid-argument", "Email required");
  }

  // Generate random 6 digit code
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // TODO: Save OTP in Firebase (Realtime DB or Firestore) for later verification
  // For example in Firestore: db.collection("otps").doc(email).set({otp, createdAt: Date.now()})

  const mailOptions = {
    from: "your-email@gmail.com",
    to: email,
    subject: "Your Verification Code",
    text: `Your OTP code is ${otp}`,
  };

  await transporter.sendMail(mailOptions);
  return { success: true, otp }; // otp only for testing, remove in production
});
