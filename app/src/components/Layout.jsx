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
          <Typography variant="h6" component="div" sx={{ cursor: 'pointer', flexGrow: 1 }} onClick={() => navigate('/')} >   
            이메일 보안 시스템
          </Typography>
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
            © 2025 이메일 연동 기반 피싱 및 악성 PDF 탐지 시스템
          </Typography>
        </Container>
      </Box>
    </Box>
  );
}; 