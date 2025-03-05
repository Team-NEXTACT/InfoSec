const axios = require("axios");

const GOOGLE_DNS_API = "https://dns.google/resolve";
const IP_API = "http://ip-api.com/json";

/**
 * 📌 Google DNS API를 사용하여 도메인의 IP 조회
 * @param {string} domain - 도메인명
 * @returns {string|null} IP 주소
 */
async function getIPAddress(domain) {
  try {
    const response = await axios.get(`${GOOGLE_DNS_API}?name=${domain}&type=A`);
    return response.data.Answer ? response.data.Answer[0].data : null;
  } catch (error) {
    console.error(`❌ Google DNS API Error: ${error.message}`);
    return null;
  }
}

/**
 * 📌 IP 정보를 조회하는 함수 (ip-api.com)
 * @param {string} ip - IP 주소
 * @returns {object | null} IP 정보
 */
async function getIPInfo(ip) {
  try {
    const response = await axios.get(`${IP_API}/${ip}?fields=country,regionName,city,isp,org,as`);

    return response.data;
  } catch (error) {
    console.error(`❌ IP-API Error: ${error.message}`);
    return null;
  }
}

/**
 * 📌 이메일 본문에서 URL을 정확하게 추출하는 함수
 * @param {string} text - 이메일 본문 (HTML 또는 텍스트)
 * @returns {Array} 추출된 URL 리스트
 */
function extractUrlsFromText(text) {
  const urls = [];

  // 🔥 URL 정규식 (HTML 태그 제거 및 특수문자 정리)
  const urlRegex = /\bhttps?:\/\/[^\s"'>]+/gi;
  const foundUrls = text.match(urlRegex) || [];

  foundUrls.forEach((url) => {
    try {
      const cleanUrl = url.replace(/["'>]+$/, ""); // 끝에 붙은 특수문자 제거
      const parsedUrl = new URL(cleanUrl);
      urls.push(parsedUrl.href);
    } catch (error) {
      console.warn(`⚠️ Invalid URL Skipped: ${url}`);
    }
  });

  return urls;
}

/**
 * 📌 이메일 본문을 찾아서 Base64 디코딩하는 함수
 * @param {object} payload - Gmail API 이메일 payload
 * @returns {string} 디코딩된 이메일 본문
 */
function extractEmailBody(payload) {
  let body = "";

  if (payload.body && payload.body.data) {
    return Buffer.from(payload.body.data, "base64").toString("utf-8");
  }

  if (payload.parts) {
    for (const part of payload.parts) {
      if (part.mimeType === "text/html" || part.mimeType === "text/plain") {
        if (part.body && part.body.data) {
          body += Buffer.from(part.body.data, "base64").toString("utf-8") + "\n";
        }
      }

      if (part.parts) {
        body += extractEmailBody(part);
      }
    }
  }

  return body;
}

/**
 * 📌 이메일에서 URL을 추출하고 분석하는 함수
 * @param {object} emailData - Gmail API 이메일 데이터
 * @returns {Array} URL 분석 결과 리스트
 */
exports.extractUrls = async (emailData) => {
  const emailBody = extractEmailBody(emailData.payload);
  const urls = extractUrlsFromText(emailBody);

  return await Promise.all(
      urls.map(async (url) => {
        try {
          const domain = new URL(url).hostname;
          const ipAddress = await getIPAddress(domain);
          const ipInfo = ipAddress ? await getIPInfo(ipAddress) : null;

          return {
            address: url,
            domain,
            ipAddress,
            ipInfo,
            isPhishingUrl: false, // 🚨 피싱 사이트 여부는 별도 데이터베이스 연동 필요
          };
        } catch (error) {
          console.error(`❌ Error processing URL: ${url} - ${error.message}`);
          return {address: url, error: "Invalid URL"};
        }
      })
  );
};
