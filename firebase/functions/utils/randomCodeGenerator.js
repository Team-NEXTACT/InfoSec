exports.randomCodeGenerator = (prefix) => {
  // Firebase ID로 사용할 대소문자+숫자 혼합 15자리 코드 생성
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = prefix;
  for (let i = 0; i < 15; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}