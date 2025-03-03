import React, { useState } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  List,
  ListItem,
  ListItemText,
  Chip,
  Box,
  Fab,
  Zoom,
  Paper,
  IconButton,
  Tooltip,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { 
  FilterList as FilterIcon, 
  Clear as ClearIcon,
  Assessment as AssessmentIcon,
  Close as CloseIcon,
} from '@mui/icons-material';

const mockResults = [
  {
    id: '1',
    fileName: 'invoice_document.pdf',
    sender: 'sender@example.com',
    recipient: 'recipient@company.com',
    securityLevel: 'dangerous',
    receivedAt: new Date('2024-03-01T10:30:00')
  },
  {
    id: '2',
    fileName: 'safe_document.pdf',
    sender: 'trusted@company.com',
    recipient: 'employee@company.com',
    securityLevel: 'safe',
    receivedAt: new Date('2024-03-01T09:15:00')
  }
];

// 7일간의 통계 데이터
const weeklyStats = {
  totalScanned: 156,
  phishingSuspicious: 23,
  dangerous: 12,
  lastUpdated: new Date()
};

export const Dashboard = () => {
  const navigate = useNavigate();
  const [activeFilter, setActiveFilter] = useState('all');
  const [showWeeklySummary, setShowWeeklySummary] = useState(true);

  // 통계 계산 함수들
  const calculateStatistics = (results) => {
    const totalFiles = results.length;
    
    const securityDistribution = {
      safe: results.filter(file => file.securityLevel === 'safe').length,
      suspicious: results.filter(file => file.securityLevel === 'suspicious').length,
      dangerous: results.filter(file => file.securityLevel === 'dangerous').length,
    };

    return {
      totalFiles,
      securityDistribution,
    };
  };

  const stats = calculateStatistics(mockResults);

  // 필터링된 결과 가져오기
  const getFilteredResults = () => {
    switch (activeFilter) {
      case 'dangerous':
        return mockResults.filter(file => file.securityLevel === 'dangerous');
      case 'suspicious':
        return mockResults.filter(file => file.securityLevel === 'suspicious');
      case 'safe':
        return mockResults.filter(file => file.securityLevel === 'safe');
      default:
        return mockResults;
    }
  };

  const handleViewDetail = (id) => {
    navigate(`/analysis/${id}`);
  };

  const handleFilterClick = (filter) => {
    setActiveFilter(filter === activeFilter ? 'all' : filter);
  };

  const getStatItemStyle = (filter) => ({
    cursor: 'pointer',
    bgcolor: activeFilter === filter ? 'action.selected' : 'transparent',
    borderRadius: 1,
    transition: 'background-color 0.2s',
    '&:hover': {
      bgcolor: 'action.hover',
    },
  });

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h4" gutterBottom>
              PDF 악성 행위 분석 대시보드
            </Typography>
            {activeFilter !== 'all' && (
              <Button startIcon={<ClearIcon />} onClick={() => setActiveFilter('all')} color="primary">
                필터 초기화
              </Button>
            )}
          </Box>
        </Grid>

        {/* 7일간 검사 요약 */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                통계
              </Typography>
              <List>
                <ListItem sx={getStatItemStyle('all')} onClick={() => handleFilterClick('all')}>
                  <ListItemText 
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <span>분석된 총 파일</span>
                        <FilterIcon 
                          fontSize="small" 
                          sx={{ 
                            ml: 1, 
                            opacity: activeFilter === 'all' ? 1 : 0,
                            color: 'primary.main'
                          }} 
                        />
                      </Box>
                    }
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Typography variant="h4" component="span" color="primary">
                          {stats.totalFiles}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                          개
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
                <ListItem sx={getStatItemStyle('dangerous')} onClick={() => handleFilterClick('dangerous')}>
                  <ListItemText 
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <span>위험 파일</span>
                        <FilterIcon 
                          fontSize="small" 
                          sx={{ 
                            ml: 1, 
                            opacity: activeFilter === 'dangerous' ? 1 : 0,
                            color: 'error.main'
                          }} 
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <Typography variant="h4" component="span" color="error">
                            {stats.securityDistribution.dangerous}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                            개
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
                <ListItem sx={getStatItemStyle('suspicious')} onClick={() => handleFilterClick('suspicious')}>
                  <ListItemText 
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <span>의심 파일</span>
                        <FilterIcon 
                          fontSize="small" 
                          sx={{ 
                            ml: 1, 
                            opacity: activeFilter === 'suspicious' ? 1 : 0,
                            color: 'warning.main'
                          }} 
                        />
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <Typography variant="h4" component="span" color="warning">
                            {stats.securityDistribution.suspicious}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                            개
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
                <ListItem sx={getStatItemStyle('safe')} onClick={() => handleFilterClick('safe')}>
                  <ListItemText 
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <span>안전 파일</span>
                        <FilterIcon 
                          fontSize="small" 
                          sx={{ 
                            ml: 1, 
                            opacity: activeFilter === 'safe' ? 1 : 0,
                            color: 'success.main'
                          }} 
                        />
                      </Box>
                    }
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Typography variant="h4" component="span" color="success.main">
                          {stats.securityDistribution.safe}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                          개
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">
                  {activeFilter === 'all' ? '최근 분석 결과' :
                   activeFilter === 'dangerous' ? '위험 파일 목록' :
                   activeFilter === 'suspicious' ? '의심 파일 목록' :
                   '안전 파일 목록'}
                </Typography>
                <Chip 
                  label={`${getFilteredResults().length}개 항목`}
                  color="primary"
                  size="small"
                />
              </Box>
              <List>
                {getFilteredResults().map((result) => (
                  <ListItem key={result.id} divider>
                    <ListItemText
                      primary={result.fileName}
                      secondary={
                        <React.Fragment>
                          <Typography component="span" variant="body2" color="text.primary">
                            발신자: {result.sender}
                          </Typography>
                          <br />
                          <Typography component="span" variant="body2" color="text.primary">
                            수신자: {result.recipient}
                          </Typography>
                          <br />
                          수신 날짜: {result.receivedAt.toLocaleString()}
                        </React.Fragment>
                      }
                    />
                    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                      <Chip
                        label={result.securityLevel === 'dangerous' ? '위험' : 
                               result.securityLevel === 'suspicious' ? '의심' : '안전'}
                        color={
                          result.securityLevel === 'dangerous'
                            ? 'error'
                            : result.securityLevel === 'suspicious'
                            ? 'warning'
                            : 'success'
                        }
                      />
                      <Button variant="outlined" size="small"
                        onClick={() => handleViewDetail(result.id)}>
                        상세보기
                      </Button>
                    </Box>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* 7일간 검사 요약 말풍선 */}
      <Zoom in={showWeeklySummary}>
        <Paper
          elevation={3}
          sx={{
            position: 'fixed',
            bottom: 100,
            right: 30,
            width: 320,
            p: 2,
            borderRadius: 2,
            '&::before': {
              content: '""',
              position: 'absolute',
              bottom: -10,
              right: 20,
              border: '10px solid transparent',
              borderTopColor: 'background.paper',
            },
          }}
        >
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6" sx={{ fontSize: '1rem' }}>
              지난 7일간 검사 요약
            </Typography>
            <IconButton size="small" onClick={() => setShowWeeklySummary(false)}>
              <CloseIcon fontSize="small" />
            </IconButton>
          </Box>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2">검사된 PDF 파일:</Typography>
              <Typography variant="h6" color="primary.main">
                {weeklyStats.totalScanned}개
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2">피싱 의심 파일:</Typography>
              <Typography variant="h6" color="warning.main">
                {weeklyStats.phishingSuspicious}개
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2">위험 파일:</Typography>
              <Typography variant="h6" color="error.main">
                {weeklyStats.dangerous}개
              </Typography>
            </Box>
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2, textAlign: 'right' }}>
            마지막 업데이트: {weeklyStats.lastUpdated.toLocaleString()}
          </Typography>
        </Paper>
      </Zoom>

      {!showWeeklySummary && (
        <Tooltip title="7일간 검사 요약 보기">
          <Fab
            color="primary"
            size="small"
            onClick={() => setShowWeeklySummary(true)}
            sx={{
              position: 'fixed',
              bottom: 30,
              right: 30,
            }}
          >
            <AssessmentIcon />
          </Fab>
        </Tooltip>
      )}
    </Box>
  );
}; 