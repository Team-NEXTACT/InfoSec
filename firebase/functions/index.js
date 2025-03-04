const functions = require("firebase-functions");
const admin = require("firebase-admin");
const express = require("express");

if (!admin.apps.length) {
  admin.initializeApp();
}

const app = express();
app.use(express.json());

app.use("/emails", require("./email/index"));

exports.api = functions.https.onRequest(app);