const {google} = require("googleapis");

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

exports.getGoogleAuth = (accessToken, refreshToken) => {
  const auth = new google.auth.OAuth2({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
  });
  auth.setCredentials({access_token: accessToken, refresh_token: refreshToken});
  return auth;
};