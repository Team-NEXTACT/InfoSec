const crypto = require('crypto');

exports.extractAttachments = (emailData) => {
  const attachments = [];

  if (emailData.payload && emailData.payload.parts) {
    emailData.payload.parts.forEach(part => {
      if (part.mimeType === "application/pdf" && part.body && part.body.data) {
        const fileBuffer = Buffer.from(part.body.data, "base64");
        const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        attachments.push({
          file_name: part.filename,
          file_type: "pdf",
          hash: hash,
          total_pages: null // pdfdist-js에서 분석 필요
        })
      }
    });
  }
  return attachments;
}