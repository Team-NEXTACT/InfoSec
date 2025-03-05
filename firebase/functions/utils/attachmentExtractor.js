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

        // ✅ 파일 크기 (KB 기준)
        const fileSize = (fileBuffer.length / 1024).toFixed(2) + "KB";

        // ✅ 해시값 생성 (MD5, SHA1, SHA256)
        const fileHash = {
          md5: crypto.createHash("md5").update(fileBuffer).digest("hex"),
          sha1: crypto.createHash("sha1").update(fileBuffer).digest("hex"),
          sha256: crypto.createHash("sha256").update(fileBuffer).digest("hex"),
        };

        // ✅ PDF 내 악성 코드 검사
        const {hasJavaScript, detectedScripts} = await analyzePDF(fileBuffer);
        const containsShellcode = await detectShellcode(fileBuffer);

        // ✅ 의심 요소 분석 (MockResult 구조에 맞춤)
        let securityLevel = "safe"; // 기본값
        let securityReason = "정상적인 파일입니다.";
        let suspiciousElements = {};

        if (hasJavaScript || containsShellcode) {
          securityLevel = "dangerous";
          securityReason = "PDF 내부에 악성 코드 포함";

          suspiciousElements = {
            pdfbox_analysis: {
              embedded_scripts: hasJavaScript,
              action_details: detectedScripts.length > 0 ? detectedScripts[0] : "N/A",
              suspicious_elements: [],
            },
          };

          if (hasJavaScript) {
            suspiciousElements.pdfbox_analysis.suspicious_elements.push({
              element: "JavaScript",
              description: "PDF 내부에서 JavaScript가 실행될 가능성이 있음.",
            });
          }

          if (containsShellcode) {
            suspiciousElements.pdfbox_analysis.suspicious_elements.push({
              element: "Shellcode",
              description: "쉘코드가 포함되어 실행 가능성이 있는 코드가 탐지됨.",
            });
          }
        }

        // ✅ Firestore 저장용 객체 (mockResult 구조 맞춤)
        attachments.push({
          fileName: part.filename,
          fileSize: fileSize,
          fileHash: fileHash,
          securityLevel: securityLevel,
          securityReason: securityReason,
          suspiciousElements: suspiciousElements,
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

  return {hasJavaScript, detectedScripts};
}
