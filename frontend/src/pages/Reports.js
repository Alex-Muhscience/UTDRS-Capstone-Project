import React, { useEffect, useState } from 'react';
import {
  Button,
  Typography,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  TextField,
  CircularProgress,
  Grid,
  useMediaQuery,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  IconButton,
  Modal,
  Card,
  CardContent,
  Pagination,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import RefreshIcon from '@mui/icons-material/Refresh';
import api from '../utils/api';

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');
  const [sort, setSort] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedReport, setSelectedReport] = useState(null);
  const theme = useTheme();
  const isSmallScreen = useMediaQuery(theme.breakpoints.down('md'));

  const pageSize = 10;

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = () => {
    setLoading(true);
    api
      .get('/reports')
      .then((response) => {
        setReports(response.data);
        setLoading(false);
      })
      .catch((error) => {
        console.error('Error fetching reports:', error);
        setError('Failed to load reports.');
        setLoading(false);
      });
  };

  const handleGenerateReport = () => {
    if (!startDate || !endDate) {
      setError('Please select both start and end dates.');
      return;
    }
    setError('');
    console.log('Fetching custom report...');
  };

  const downloadReport = (format, reportId) => {
    console.log(`Downloading ${format} report for Report ID: ${reportId}`);
  };

  const handleFilterChange = (event) => {
    setFilter(event.target.value);
  };

  const handleSortChange = (event) => {
    setSort(event.target.value);
  };

  const handlePageChange = (event, value) => {
    setCurrentPage(value);
  };

  const handleReportClick = (report) => {
    setSelectedReport(report);
  };

  const handleCloseModal = () => {
    setSelectedReport(null);
  };

  if (loading) {
    return (
      <Box sx={{ textAlign: 'center', padding: '2rem' }}>
        <CircularProgress />
        <Typography>Loading Reports...</Typography>
      </Box>
    );
  }

  const filteredReports = reports
    .filter((report) => (filter ? report.type === filter : true))
    .sort((a, b) => {
      if (sort === 'date') {
        return new Date(b.date) - new Date(a.date);
      } else if (sort === 'type') {
        return a.type.localeCompare(b.type);
      } else if (sort === 'id') {
        return a.id - b.id;
      }
      return 0;
    });

  const paginatedReports = filteredReports.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  return (
    <Box sx={{ padding: '2rem' }}>
      <Grid container spacing={3} alignItems="center" marginBottom="1.5rem">
        <Grid item xs={10}>
          <Typography variant="h4" gutterBottom>
            Reports
          </Typography>
        </Grid>
        <Grid item xs={2} sx={{ textAlign: 'right' }}>
          <IconButton color="primary" onClick={fetchReports}>
            <RefreshIcon />
          </IconButton>
        </Grid>
      </Grid>
      {error && <Typography color="error" gutterBottom>{error}</Typography>}
      <Grid container spacing={3} alignItems="center" marginBottom="1.5rem">
        <Grid item xs={12} md={4}>
          <TextField
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            label="Start Date"
            fullWidth
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TextField
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            label="End Date"
            fullWidth
          />
        </Grid>
        <Grid item xs={12} md={2}>
          <Button
            variant="contained"
            color="primary"
            onClick={handleGenerateReport}
            fullWidth={isSmallScreen}
          >
            Generate Report
          </Button>
        </Grid>
      </Grid>
      <Grid container spacing={3} alignItems="center" marginBottom="1rem">
        <Grid item xs={12} md={4}>
          <FormControl fullWidth>
            <InputLabel>Filter by Type</InputLabel>
            <Select value={filter} onChange={handleFilterChange}>
              <MenuItem value="">None</MenuItem>
              <MenuItem value="Type1">Type 1</MenuItem>
              <MenuItem value="Type2">Type 2</MenuItem>
              <MenuItem value="Type3">Type 3</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12} md={4}>
          <FormControl fullWidth>
            <InputLabel>Sort by</InputLabel>
            <Select value={sort} onChange={handleSortChange}>
              <MenuItem value="">None</MenuItem>
              <MenuItem value="date">Date</MenuItem>
              <MenuItem value="type">Type</MenuItem>
              <MenuItem value="id">ID</MenuItem>
            </Select>
          </FormControl>
        </Grid>
      </Grid>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Date</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {paginatedReports.map((report) => (
              <TableRow key={report.id} onClick={() => handleReportClick(report)}>
                <TableCell>{report.id}</TableCell>
                <TableCell>{report.date}</TableCell>
                <TableCell>{report.type}</TableCell>
                <TableCell>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={() => downloadReport('pdf', report.id)}
                    sx={{ marginRight: '0.5rem' }}
                  >
                    PDF
                  </Button>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => downloadReport('csv', report.id)}
                  >
                    CSV
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <Pagination
          count={Math.ceil(filteredReports.length / pageSize)}
          page={currentPage}
          onChange={handlePageChange}
          sx={{ padding: '1rem', justifyContent: 'center', display: 'flex' }}
        />
      </TableContainer>
      <Modal open={!!selectedReport} onClose={handleCloseModal}>
        <Card sx={{ maxWidth: 400, margin: 'auto', marginTop: '10%', padding: '1rem' }}>
          <CardContent>
            {selectedReport && (
              <>
                <Typography variant="h5">Report Details</Typography>
                <Typography>ID: {selectedReport.id}</Typography>
                <Typography>Date: {selectedReport.date}</Typography>
                <Typography>Type: {selectedReport.type}</Typography>
              </>
            )}
          </CardContent>
        </Card>
      </Modal>
    </Box>
  );
};

export default Reports;
