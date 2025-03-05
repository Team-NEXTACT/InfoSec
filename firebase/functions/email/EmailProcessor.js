const admin = require("firebase-admin");
const {Timestamp} = require("firebase-admin/firestore")
const {google} = require("googleapis");
const {getGoogleAuth} = require("../utils/googleAuth");
const {extractUrls} = require("../utils/urlExtractor");
const {extractAttachments} = require("../utils/attachmentExtractor");
const {randomCodeGenerator} = require("../utils/randomCodeGenerator");

const db = admin.firestore();

class EmailProcessor {
  constructor(accessToken, refreshToken, email) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.email = email;
    this.auth = getGoogleAuth(accessToken, refreshToken);
    this.gmail = google.gmail({version: "v1", auth: this.auth});
  }

  async fetchUser() {
    const userRef = db.collection("users").where("email", "==", this.email);
    const snapshot = await userRef.get();
    if (snapshot.empty) {
      throw new Error("사용자를 찾을 수 없습니다.");
    }

    return {
      user: snapshot.docs[0].data(),
      userId: snapshot.docs[0].id,
    };
  }

  async fetchEmails(lastAnalyzedAt) {
    const query = lastAnalyzedAt ? `after:${lastAnalyzedAt}` : "";
    const response = await this.gmail.users.messages.list({
      userId: "me",
      q: query,
      maxResults: 5,
    });

    return response.data.messages || [];
  }

  async processEmails(messages, userId) {
    let batch = db.batch();

    for await (const message of messages) {
      const emailData = (
          await this.gmail.users.messages.get({
            userId: "me",
            id: message.id,
            format: "full",
          })
      ).data;

      const emailId = randomCodeGenerator("email_");

      // 📌 URL & 첨부파일 분석을 병렬 처리하여 성능 향상
      const [urls, attachments] = await Promise.all([
        extractUrls(emailData),
        extractAttachments(emailData),
      ]);

      // 📌 Firestore 저장
      const emailRef = db.collection("emails").doc(emailId);
      batch.set(emailRef, {
        id: emailId,
        user_id: userId,
        sender: emailData.payload.headers.find((h) => h.name === "From")?.value || "Unknown",
        receiver: emailData.payload.headers.find((h) => h.name === "To")?.value || "Unknown",
        subject: emailData.payload.headers.find((h) => h.name === "Subject")?.value || "No Subject",
        received_at: Math.floor(emailData.internalDate / 1000),
        analyzed: true,
        analyzed_at: Timestamp.now(),
        has_risky_attachment: attachments.some((att) => att.securityLevel === "dangerous"),
        has_risky_url: urls.some((url) => url.isPhishingUrl === true),
        attachment_data: attachments,
        url_data: urls.map(({address, domain, ipAddress, ipInfo, isPhishingUrl}) => ({
          address,
          domain,
          ipAddress,
          ipInfo,
          isPhishingUrl,
        })), // WHOIS 관련 정보 제거
        email_risk: this.assessEmailRisk(attachments, urls),
      });
    }

    // ✅ 배치 커밋 + last_analysis_at 업데이트
    await batch.commit();
    await db.collection("users").doc(userId).update(
        {last_analysis_at: Timestamp.now()});
  }

  /**
   * 📌 이메일의 전체 위험 수준을 평가하는 함수
   * @param {Array} attachments - 분석된 첨부파일 리스트
   * @param {Array} urls - 분석된 URL 리스트
   * @returns {string} 위험 수준 ("safe" | "suspicious" | "dangerous")
   */
  assessEmailRisk(attachments, urls) {
    let riskLevel = "safe";

    // 1️⃣ 첨부파일 분석 결과 반영
    if (attachments.some((att) => att.securityLevel === "dangerous")) {
      riskLevel = "dangerous";
    } else if (attachments.some((att) => att.securityLevel === "suspicious")) {
      riskLevel = "suspicious";
    }

    // 2️⃣ URL 분석 결과 반영
    if (urls.some((url) => url.isPhishingUrl === true)) {
      riskLevel = "dangerous";
    }

    return riskLevel;
  }
}

module.exports = EmailProcessor;
