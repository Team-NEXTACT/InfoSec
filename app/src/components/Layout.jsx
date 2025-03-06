import React from 'react';
import { AppBar, Toolbar, Typography, Container, Box, IconButton } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { Settings as SettingsIcon } from '@mui/icons-material';

export const Layout = ({ children }) => {
  const navigate = useNavigate();

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar>
          <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, cursor: 'pointer' }} onClick={() => navigate('/')}>
            <Typography variant="h6" component="div">   
              PDFense
            </Typography>
            <Typography variant="subtitle2" component="div">
              이메일 위험 요소 분석
            </Typography>
          </Box>
          <IconButton color="inherit" onClick={() => navigate('/settings')} aria-label="설정">
            <SettingsIcon />
          </IconButton>
        </Toolbar>
      </AppBar>
      <Container component="main" sx={{ mt: 4, mb: 4, flex: 1 }}>
        {children}
      </Container>
      <Box component="footer" sx={{ py: 3, bgcolor: 'background.paper' }}>
        <Container maxWidth="sm">
          <Typography variant="body2" color="text.secondary" align="center">
            © 2025 이메일 연동 기반 피싱 URL 및 악성 PDF 탐지 시스템
          </Typography>
        </Container>
      </Box>
    </Box>
  );
}; 