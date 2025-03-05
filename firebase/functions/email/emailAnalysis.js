const admin = require("firebase-admin");

const db = admin.firestore();

/**
 * 특정 사용자(userId)의 이메일 분석 데이터를 조회하는 API
 */
exports.getEmailAnalysis = async (req, res) => {
  try {
    const {userId} = req.query;

    if (!userId) {
      return res.status(400).json({error: "userId가 필요합니다."});
    }

    // Firestore에서 특정 사용자의 이메일만 가져오고, 최대 10개 제한
    const emailSnapshot = await db
    .collection("emails")
    .where("user_id", "==", userId) // 🔹 특정 사용자만 필터링
    .orderBy("received_at", "desc") // 최근 이메일부터 정렬
    .limit(10) // 최대 10개만 조회
    .get();

    if (emailSnapshot.empty) {
      return res.status(404).json({error: "이메일 분석 데이터가 없습니다."});
    }

    const emails = emailSnapshot.docs.map((doc) => {
      const emailData = doc.data();
      return {
        id: doc.id, // 🔹 Firestore 문서 ID 포함
        subject: emailData.subject || "제목 없음",
        sender: emailData.sender || "Unknown",
        recipient: emailData.receiver || "Unknown",
        securityLevel: emailData.email_risk,
        securityReason: emailData.has_risky_url
            ? "피싱 URL 포함"
            : emailData.has_risky_attachment
                ? "위험한 첨부파일 포함"
                : "안전한 이메일",
        receivedAt: new Date(emailData.received_at * 1000),
      };
    });

    return res.status(200).json(emails);
  } catch (error) {
    console.error("Error fetching email analysis:", error);
    return res.status(500).json({error: "서버 오류 발생"});
  }
};

