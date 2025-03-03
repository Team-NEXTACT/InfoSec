import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
} from '@mui/material';
import { Delete as DeleteIcon, Add as AddIcon } from '@mui/icons-material';

export const Settings = () => {
  const [profile, setProfile] = useState({
    displayName: '사용자',
    email: 'personal@gmail.com',
  });

  const [notifications, setNotifications] = useState({
    emailNotifications: true,
    deleteDangerousFiles: true,
  });

  const [connectedEmails, setConnectedEmails] = useState([
    { email: 'company@gmail.com', type: '회사 이메일' },
    { email: 'personal@gmail.com', type: '개인 이메일' },
  ]);

  const [newEmail, setNewEmail] = useState('');
  const [showSuccess, setShowSuccess] = useState(false);

  const handleProfileUpdate = () => {
    // TODO: API 호출로 프로필 업데이트
    setShowSuccess(true);
    setTimeout(() => setShowSuccess(false), 3000);
  };

  const handleNotificationChange = (setting) => (event) => {
    setNotifications({
      ...notifications,
      [setting]: event.target.checked,
    });
  };

  const handleEmailAdd = () => {
    if (newEmail) {
      setConnectedEmails([...connectedEmails, { email: newEmail, type: '추가 이메일' }]);
      setNewEmail('');
    }
  };

  const handleEmailDelete = (email) => {
    setConnectedEmails(connectedEmails.filter(e => e.email !== email));
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom> 사용자 설정 </Typography>

      {showSuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          설정이 성공적으로 저장되었습니다.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* 프로필 설정 */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom> 프로필 설정 </Typography>
              <Box component="form" sx={{ mt: 2 }}>
                <TextField fullWidth label="이름" value={profile.displayName}
                    onChange={(e) => setProfile({ ...profile, displayName: e.target.value })} margin="normal" />
                <TextField fullWidth label="기본 이메일" value={profile.email}
                    onChange={(e) => setProfile({ ...profile, email: e.target.value })} margin="normal" />
                <Button variant="contained" color="primary" onClick={handleProfileUpdate} sx={{ mt: 2 }}>
                  프로필 업데이트
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* 알림 설정 */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom> 활성화 여부 </Typography>
              <List>
                <ListItem>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={notifications.emailNotifications}
                        onChange={handleNotificationChange('emailNotifications')}
                      />
                    }
                    label="위험 파일 알림"
                  />
                </ListItem>
                <ListItem>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={notifications.deleteDangerousFiles}
                        onChange={handleNotificationChange('deleteDangerousFiles')}
                      />
                    }
                    label="위험 파일 자동 삭제"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* 이메일 연동 설정 */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom> 이메일 연동 설정 </Typography>
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  연동된 이메일 계정
                </Typography>
                <List>
                  {connectedEmails.map((email) => (
                    <ListItem key={email.email}>
                      <ListItemText
                        primary={email.email}
                        secondary={email.type}
                      />
                      <ListItemSecondaryAction>
                        <IconButton
                          edge="end"
                          aria-label="delete"
                          onClick={() => handleEmailDelete(email.email)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              </Box>
              <Divider sx={{ my: 2 }} />
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
                <TextField label="새 이메일 추가" value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)} sx={{ flexGrow: 1 }} />
                <Button variant="contained" startIcon={<AddIcon />} onClick={handleEmailAdd} sx={{ mt: 1 }}>
                  추가
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}; 