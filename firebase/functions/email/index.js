const express = require("express");
const {fetchEmails} = require("./fetchEmails");
const {getEmailAnalysis} = require("./emailAnalysis");
const {getEmailAnalysisDetail} = require("./getEmailAnalysisDetail");

const router = express.Router();

router.post("/", fetchEmails);
router.get("/analysis", getEmailAnalysis);
router.get("/analysis-detail/:email_id", getEmailAnalysisDetail);

module.exports = router;