import React, {useEffect} from 'react';
import {useLocation, useNavigate} from 'react-router-dom';
import {Box, CircularProgress, Typography} from '@mui/material';

const fetchEmails = async (accessToken, refreshToken, email, navigate) => {
  try {
    await fetch('http://127.0.0.1:5001/pdf-security/us-central1/api/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({accessToken, refreshToken, email}),
    });
    navigate('/dashboard'); // 완료 후 대시보드로 이동
  } catch (error) {
    console.error('이메일 분석 실패:', error);
    navigate('/dashboard'); // 실패해도 이동
  }
};

const LoadingPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const {accessToken, refreshToken, email} = location.state || {};

  useEffect(() => {
    if (!accessToken || !refreshToken || !email) {
      navigate('/'); // 데이터가 없으면 홈으로 이동
      return;
    }
    fetchEmails(accessToken, refreshToken, email, navigate);
  }, [accessToken, refreshToken, email, navigate]);

  return (
      <Box
          sx={{
            height: '100vh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: 'background.default',
          }}
      >
        <CircularProgress size={80} sx={{mb: 3}}/>
        <Typography variant="h6" color="textSecondary">
          이메일 분석 중입니다...
        </Typography>
      </Box>
  );
};

export default LoadingPage;
