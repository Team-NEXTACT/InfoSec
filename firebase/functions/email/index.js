const express = require("express");
const {fetchEmails} = require("./fetchEmails");

const router = express.Router();

router.post("/", fetchEmails);

module.exports = router;