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
      maxResults: 30,
    });

    return response.data.messages || [];
  }

  async processEmails(messages, userId) {
    const batch = db.batch();
    const urlBatch = db.batch();
    const attachmentBatch = db.batch();

    const emailPromises = messages.map(async (message) => {
      const emailData = (await this.gmail.users.messages.get({
        userId: "me",
        id: message.id,
      })).data;

      const emailId = randomCodeGenerator("email_");  // ✨ 랜덤 ID 사용
      const urls = extractUrls(emailData) || [];  // ✅ undefined 방지
      const attachments = extractAttachments(emailData) || [];  // ✅ undefined 방지

      const urlIds = urls.length > 0 ? urls.map(() => randomCodeGenerator("url_")) : [];  // ✅ 빈 배열이면 map() 실행 안 함
      const attachmentIds = attachments.length > 0 ? attachments.map(() => randomCodeGenerator("pdf_")) : [];  // ✅ 빈 배열이면 map() 실행 안 함

      // 📌 이메일 저장 (랜덤 ID)
      const emailRef = db.collection("emails").doc(emailId);
      batch.set(emailRef, {
        id: emailId,
        user_id: userId,
        sender: emailData.payload.headers.find(h => h.name === "From")?.value || "Unknown",
        subject: emailData.payload.headers.find(h => h.name === "Subject")?.value || "No Subject",
        spf: "",
        dkim: "",
        dmars: "",
        received_at: Math.floor(emailData.internalDate / 1000),
        analyzed: false,
        analyzed_at: Math.floor(Date.now() / 1000), // ✅ 현재 시간을 초 단위 UNIX 타임스탬프로 저장
        has_risky_attachment: attachmentIds.length > 0,
        has_risky_url: urlIds.length > 0,
        attachment_ids: attachmentIds,
        url_ids: urlIds,
      });

      // 📌 URL 분석 문서 저장 (랜덤 ID)
      urls.forEach((url, index) => {
        const urlRef = db.collection("url_analysis").doc(urlIds[index]);
        urlBatch.set(urlRef, {
          id: urlIds[index],
          address: url,
          virus_total_score: null,
          virus_total_results: {},
          redirects: [],
          whois: {},
          overall_risk: "pending",
        });
      });

      // 📌 첨부파일 분석 문서 저장 (랜덤 ID)
      attachments.forEach((att, index) => {
        const attachmentRef = db.collection("attachment_analysis").doc(attachmentIds[index]);
        attachmentBatch.set(attachmentRef, {
          id: attachmentIds[index],
          file_name: att.file_name,
          file_type: "pdf",
          hash: att.hash,
          total_pages: att.total_pages,
          virus_total_score: null,
          pdf_analysis: {},
          overall_risk: "pending",
        });
      });
    });

    await Promise.all(emailPromises);
    await batch.commit();
    await urlBatch.commit();
    await attachmentBatch.commit();
  }
}

module.exports = EmailProcessor;
