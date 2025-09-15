const express = require("express");
const app = express();
const PORT = 3000;

let dataStore = []; // memory me data rakha ja raha hai

app.use(express.json());

// ✅ Test route
app.get("/", (req, res) => {
  res.send("EMS API is running 🚀");
});

// ✅ POST API: Data receive from ESP32
app.post("/data", (req, res) => {
  const { device, voltage, current, timestamp } = req.body;

  const newData = {
    device,
    voltage,
    current,
    timestamp: new Date(timestamp) // string ko Date object banate hain
  };

  dataStore.push(newData);

  console.log("Data received:", newData);

  res.json({
    message: "Data received successfully ✅",
    data: newData
  });
});

// ✅ GET API: Sara raw data
app.get("/data", (req, res) => {
  res.json({
    message: "All stored EMS data 📊",
    data: dataStore
  });
});

// ✅ GET API: Monthly total & average (full ghar ka)
app.get("/monthly-summary/:year/:month", (req, res) => {
  const { year, month } = req.params;

  // Filter data jo is year + month ka hai
  const monthlyData = dataStore.filter(item => {
    return (
      item.timestamp.getFullYear() === parseInt(year) &&
      item.timestamp.getMonth() + 1 === parseInt(month) // JS months 0-based hote hain
    );
  });

  if (monthlyData.length === 0) {
    return res.json({
      message: "No data found for this month ❌",
      totalVoltage: 0,
      totalCurrent: 0,
      avgVoltage: 0,
      avgCurrent: 0
    });
  }

  // Totals nikalna
  const totalVoltage = monthlyData.reduce((sum, item) => sum + item.voltage, 0);
  const totalCurrent = monthlyData.reduce((sum, item) => sum + item.current, 0);

  // Averages nikalna
  const avgVoltage = totalVoltage / monthlyData.length;
  const avgCurrent = totalCurrent / monthlyData.length;

  res.json({
    message: "Monthly summary 📊",
    year,
    month,
    totalVoltage,
    totalCurrent,
    avgVoltage,
    avgCurrent
  });
});
const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

// Generate random 6-digit OTP
function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// In-memory store for demo (production: Firestore / Realtime DB)
let otpStore = {};

exports.sendOtp = functions.https.onCall(async (data, context) => {
    const email = data.email;
    if (!email) {
        throw new functions.https.HttpsError('invalid-argument', 'Email is required');
    }

    const otp = generateOtp();
    const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes

    // Save OTP in memory (replace with DB in production)
    otpStore[email] = { otp, expiry };

    console.log(`OTP for ${email}: ${otp} (valid 5 min)`);

    return { otp }; // app ko OTP send kar raha hai
});

// Optional: verify OTP
exports.verifyOtp = functions.https.onCall(async (data, context) => {
    const { email, otp } = data;
    const record = otpStore[email];

    if (!record) throw new functions.https.HttpsError('not-found', 'No OTP found');
    if (record.expiry < Date.now()) throw new functions.https.HttpsError('deadline-exceeded', 'OTP expired');
    if (record.otp !== otp) throw new functions.https.HttpsError('invalid-argument', 'Invalid OTP');

    delete otpStore[email]; // OTP used
    return { success: true };
});
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});