import React from 'react';
import {Button} from '@mui/material';
import {useNavigate} from 'react-router-dom';
import {getAuth, GoogleAuthProvider, signInWithPopup} from 'firebase/auth';
import app from '../firebaseConfig';

const auth = getAuth(app);
const provider = new GoogleAuthProvider(auth);
provider.addScope('https://www.googleapis.com/auth/gmail.readonly');

const StartButton = () => {
  const navigate = useNavigate();

  const handleLogin = async () => {
    try {
      const result = await signInWithPopup(auth, provider);
      const credential = GoogleAuthProvider.credentialFromResult(result);
      const accessToken = credential.accessToken;
      const refreshToken = result.user.refreshToken;
      const email = result.user.email;

      navigate('/loading', {state: {accessToken, refreshToken, email}}); // 로딩 페이지로 이동
    } catch (error) {
      console.error(`로그인 실패: ${error}`);
    }
  };

  return (
      <Button
          variant="contained"
          size="large"
          onClick={handleLogin}
          sx={{
            bgcolor: 'white',
            color: 'primary.main',
            borderRadius: '30px',
            px: 4,
            py: 1.5,
            fontSize: '1.2rem',
            textTransform: 'none',
            boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
            transition: 'all 0.3s ease',
            '&:hover': {
              bgcolor: '#f5f5f5',
              color: 'primary.main',
              boxShadow: '0 8px 16px rgba(0, 0, 0, 0.2)',
              transform: 'scale(1.05)',
            },
          }}
      >
        Sign in with Google
      </Button>
  );
};

export default StartButton;