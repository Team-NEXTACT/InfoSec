const EmailProcessor = require("./EmailProcessor");

exports.fetchEmails = async (req, res) => {
  const {accessToken, refreshToken, email} = req.body;
  if (!accessToken || !refreshToken || !email) {
    return res.status(400).send({error: "사용자 정보가 부족합니다."});
  }

  try {
    const processor = new EmailProcessor(accessToken, refreshToken, email);
    const {user, userId} = await processor.fetchUser();
    const lastAnalyzedAt = user.last_analyzed_at ? user.last_analyzed_at.seconds : null;
    const messages = await processor.fetchEmails(lastAnalyzedAt);

    if (messages.length === 0) {
      return res.status(200).send({message: "분석할 이메일이 없습니다."});
    }

    await processor.processEmails(messages, userId);
    res.status(200).send({message: "이메일 저장 및 분석 준비 완료"});
  } catch (error) {
    console.error("이메일 처리 중 오류 발생:", error);
    res.status(500).send({error: error.message});
  }
};
