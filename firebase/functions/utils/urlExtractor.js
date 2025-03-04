const whois = require("whois-json");
const validUrl = require("valid-url");

exports.extractUrls = async (emailData) => {
  const urls = [];

  if (emailData.payload && emailData.payload.parts) {
    emailData.payload.parts.forEach((part) => {
      if (part.mimeType === "text/html" || part.mimeType === "text/plain") {
        const decodedBody = Buffer.from(part.body.data, "base64").toString("utf-8");
        const foundUrls = decodedBody.match(/\bhttps?:\/\/\S+/gi) || [];
        urls.push(...foundUrls);
      }
    });
  }

  // 📌 URL 분석 (WHOIS 조회만 수행)
  return await Promise.all(
      urls.map(async (url) => {
        const whoisData = validUrl.isUri(url) ? await whois(url) : null;

        return {
          address: url,
          whoisData,
        };
      })
  );
};
