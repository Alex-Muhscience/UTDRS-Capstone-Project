import React, { useEffect, useState } from "react";
import {
  Grid,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Snackbar,
  Alert,
  useMediaQuery,
  Box,
  List,
  ListItem,
  ListItemText,
  IconButton,
} from "@mui/material";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Refresh } from "@mui/icons-material";
import { useTheme } from "@mui/material/styles";
import api from "../utils/api";

const Dashboard = () => {
  const [threatData, setThreatData] = useState([]);
  const [recentThreats, setRecentThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [snackbarMessage, setSnackbarMessage] = useState("");
  const themeUI = useTheme();
  const isSmallScreen = useMediaQuery(themeUI.breakpoints.down("md"));

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = () => {
    setLoading(true);
    api
      .get("/dashboard-data")
      .then((response) => {
        setThreatData(response.data.threatSummary);
        setRecentThreats(response.data.recentThreats);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching dashboard data:", error);
        setError("Failed to load dashboard data.");
        setLoading(false);
      });
  };

  const handleRefresh = () => {
    fetchDashboardData();
    setSnackbarMessage("Dashboard data refreshed!");
  };

  const handleCloseSnackbar = () => {
    setSnackbarMessage("");
  };

  if (loading) {
    return (
      <Box sx={{ textAlign: "center", padding: "2rem" }}>
        <CircularProgress />
        <Typography>Loading Dashboard...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ padding: "2rem" }}>
      <Grid container spacing={3} alignItems="center">
        <Grid item xs={10}>
          <Typography variant="h4" gutterBottom>
            Threat Detection Dashboard
          </Typography>
        </Grid>
        <Grid item xs={2} sx={{ textAlign: "right" }}>
          <IconButton onClick={handleRefresh} color="primary">
            <Refresh />
          </IconButton>
        </Grid>
      </Grid>
      {error && <Typography color="error" gutterBottom>{error}</Typography>}

      <Grid container spacing={3}>
        {/* Threat Overview */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                Threat Overview
              </Typography>
              <BarChart
                width={isSmallScreen ? 300 : 600}
                height={isSmallScreen ? 200 : 300}
                data={threatData}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" fill="#3f51b5" />
              </BarChart>
            </CardContent>
          </Card>
        </Grid>

        {/* Real-time Threat Level */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                Real-time Threat Level
              </Typography>
              <LineChart
                width={isSmallScreen ? 300 : 600}
                height={isSmallScreen ? 200 : 300}
                data={threatData}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#8884d8" />
              </LineChart>
            </CardContent>
          </Card>
        </Grid>

        {/* Threat Distribution */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                Threat Distribution
              </Typography>
              <PieChart width={isSmallScreen ? 300 : 600} height={isSmallScreen ? 200 : 300}>
                <Pie
                  data={threatData}
                  dataKey="count"
                  nameKey="type"
                  cx="50%"
                  cy="50%"
                  outerRadius={isSmallScreen ? 80 : 120}
                  fill="#8884d8"
                  label
                >
                  {threatData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={index % 2 === 0 ? "#8884d8" : "#82ca9d"}
                    />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Threats */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h5" gutterBottom>
                Recent Threats
              </Typography>
              <List>
                {recentThreats.length > 0 ? (
                  recentThreats.map((threat, index) => (
                    <ListItem key={index} divider>
                      <ListItemText
                        primary={`Type: ${threat.type}`}
                        secondary={
                          <>
                            <Typography
                              component="span"
                              variant="body2"
                              color="textPrimary"
                            >
                              Severity: {threat.severity}
                            </Typography>
                            <br />
                            <Typography
                              component="span"
                              variant="body2"
                              color="textSecondary"
                            >
                              Source: {threat.source}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                  ))
                ) : (
                  <Typography>No recent threats found.</Typography>
                )}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Snackbar for notifications */}
      <Snackbar
        open={!!snackbarMessage}
        autoHideDuration={3000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert onClose={handleCloseSnackbar} severity="success" sx={{ width: "100%" }}>
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Dashboard;
