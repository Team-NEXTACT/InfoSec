const admin = require("firebase-admin");
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
      const emailData = (await this.gmail.users.messages.get({
        userId: "me",
        id: message.id,
        format: "full",
      })).data;

      const emailId = randomCodeGenerator("email_");

      // 📌 URL & 첨부파일 분석을 병렬 처리하여 성능 향상
      const [urls, attachments] = await Promise.all([
        extractUrls(emailData),
        extractAttachments(emailData),
      ]);

      // 📌 Firestore에는 분석된 데이터만 저장 (파일 X)
      const emailRef = db.collection("emails").doc(emailId);
      batch.set(emailRef, {
        id: emailId,
        user_id: userId,
        sender: emailData.payload.headers.find((h) => h.name === "From")?.value || "Unknown",
        receiver: emailData.payload.headers.find((h) => h.name === "To")?.value || "Unknown",
        subject: emailData.payload.headers.find((h) => h.name === "Subject")?.value || "No Subject",
        received_at: Math.floor(emailData.internalDate / 1000),
        analyzed: true,
        analyzed_at: Math.floor(Date.now() / 1000),
        has_risky_attachment: attachments.length > 0,
        has_risky_url: urls.length > 0,
        attachment_data: attachments, // 파일 원본이 아니라 분석 결과만 저장
        url_data: urls, // URL 원본이 아니라 위험도 정보만 저장
        email_risk: this.assessEmailRisk(attachments, urls),
      });

    }
    await batch.commit();
  }

  assessEmailRisk(attachments, urls) {
    let riskLevel = "안전";
    if (attachments.length > 0 || urls.some((u) => u.risk_level === "의심")) {
      riskLevel = "의심";
    }
    if (attachments.some((att) => att.hash === "known_malicious_hash")) {
      riskLevel = "위험";
    }
    return riskLevel;
  }
}

module.exports = EmailProcessor;
