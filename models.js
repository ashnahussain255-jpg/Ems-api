const mongoose = require("mongoose");

// 1-sec raw data
const RawDataSchema = new mongoose.Schema({
  device: String,
  voltage: Number,
  current: Number,
  timestamp: { type: Date, default: Date.now }
});
const RawData = mongoose.model("RawData", RawDataSchema);

// Aggregated schemas
const AvgSchema = new mongoose.Schema({
  startTime: Date,
  endTime: Date,
  device: String,
  avgVoltage: Number,
  avgCurrent: Number
});

const Avg30Sec = mongoose.model("Avg30Sec", AvgSchema);
const Avg1Min = mongoose.model("Avg1Min", AvgSchema);
const Avg1Hour = mongoose.model("Avg1Hour", AvgSchema);
const Avg1Day = mongoose.model("Avg1Day", AvgSchema);
const Avg30Day = mongoose.model("Avg30Day", AvgSchema);

module.exports = { RawData, Avg30Sec, Avg1Min, Avg1Hour, Avg1Day, Avg30Day };