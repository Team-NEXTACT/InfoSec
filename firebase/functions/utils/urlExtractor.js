exports.extractUrls = (emailData) => {
  const urls = [];

  if (emailData.payload && emailData.payload.parts) {
    emailData.payload.parts.forEach(part => {
      if (part.mimeType === "text/html" || part.mimeType === "text/plain") {
        const decodedBody = Buffer.from(part.body.data, "base64").toString("utf-8");
        const foundUrls = decodedBody.match(/\bhttps?:\/\/\S+/gi) || [];
        urls.push(...foundUrls);
      }
    });
    return urls;
  }
}