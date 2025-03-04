const crypto = require("crypto");

// 🚨 추가할 Shellcode 탐지 로직 (yara 사용 가능)
async function detectShellcode(pdfBuffer) {
  // yara-wasm 또는 특정 패턴 탐지 방식 적용 가능
  return false; // 기본적으로 false 반환
}

exports.extractAttachments = async (emailData) => {
  const attachments = [];

  if (emailData.payload && emailData.payload.parts) {
    for (const part of emailData.payload.parts) {
      if (part.mimeType === "application/pdf" && part.body && part.body.data) {
        const fileBuffer = Buffer.from(part.body.data, "base64");
        const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        const {totalPages, hasJavaScript, detectedScripts} = await analyzePDF(fileBuffer);
        const containsShellcode = await detectShellcode(fileBuffer);

        // Firestore에는 파일을 저장하지 않고 분석 결과만 저장
        attachments.push({
          file_name: part.filename,
          file_type: "pdf",
          hash: hash,
          total_pages: totalPages, // PDF 페이지 수 저장
          has_javascript: hasJavaScript, // JavaScript 포함 여부
          detected_scripts: detectedScripts, // 감지된 스크립트 내용 일부
          contains_shellcode: containsShellcode, // Shellcode 포함 여부
        });
      }
    }
  }

  return attachments;
};

// 📌 PDF 분석 함수 - JavaScript 코드 포함 여부 분석
async function analyzePDF(pdfBuffer) {
  const pdfjs = await import("pdfjs-dist/build/pdf.mjs"); // ✅ 동적 import 사용 (ESM 문제 해결)
  const pdf = await pdfjs.getDocument({data: pdfBuffer}).promise;

  let hasJavaScript = false;
  let detectedScripts = [];

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const annotations = await page.getAnnotations();

    // 📌 PDF 내 JavaScript 검사
    annotations.forEach((annotation) => {
      if (annotation.subtype === "Widget" && annotation.AA) {
        for (const key in annotation.AA) {
          if (annotation.AA[key].JS) {
            hasJavaScript = true;
            detectedScripts.push(annotation.AA[key].JS.substring(0, 100)); // 스크립트 일부만 저장
          }
        }
      }
    });
  }

  return {totalPages: pdf.numPages, hasJavaScript, detectedScripts};
}
