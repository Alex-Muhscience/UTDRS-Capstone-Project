import React, { useState } from "react";
import {
  Box,
  Typography,
  Slider,
  Switch,
  Button,
  FormControlLabel,
  CircularProgress,
  Snackbar,
  Alert,
  Grid,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TextField,
} from "@mui/material";

const Settings = () => {
  const [threshold, setThreshold] = useState(70);
  const [autoResponse, setAutoResponse] = useState(false);
  const [notificationsEnabled, setNotificationsEnabled] = useState(true);
  const [theme, setTheme] = useState("light");
  const [language, setLanguage] = useState("en");
  const [incidentRetention, setIncidentRetention] = useState(30);
  const [responseDelay, setResponseDelay] = useState(5);
  const [loading, setLoading] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState("");

  const saveSettings = () => {
    setLoading(true);
    // Simulate API call
    setTimeout(() => {
      setLoading(false);
      setSnackbarMessage("Settings saved successfully!");
    }, 2000);
  };

  const resetSettings = () => {
    setLoading(true);
    // Simulate API call
    setTimeout(() => {
      setThreshold(70);
      setAutoResponse(false);
      setNotificationsEnabled(true);
      setTheme("light");
      setLanguage("en");
      setIncidentRetention(30);
      setResponseDelay(5);
      setLoading(false);
      setSnackbarMessage("Settings reset to defaults.");
    }, 2000);
  };

  const handleCloseSnackbar = () => {
    setSnackbarMessage("");
  };

  return (
    <Box sx={{ padding: "2rem" }}>
      <Typography variant="h4" gutterBottom>
        System Settings
      </Typography>
      <Grid container spacing={4} alignItems="center">
        {/* Detection Threshold */}
        <Grid item xs={12} md={6}>
          <Typography gutterBottom>Detection Threshold (%)</Typography>
          <Slider
            value={threshold}
            onChange={(e, val) => setThreshold(val)}
            min={0}
            max={100}
            step={5}
            valueLabelDisplay="auto"
            fullWidth
          />
        </Grid>

        {/* Automated Responses */}
        <Grid item xs={12} md={6}>
          <FormControlLabel
            control={
              <Switch
                checked={autoResponse}
                onChange={(e) => setAutoResponse(e.target.checked)}
              />
            }
            label="Enable Automated Responses"
          />
        </Grid>

        {/* Notifications */}
        <Grid item xs={12} md={6}>
          <FormControlLabel
            control={
              <Switch
                checked={notificationsEnabled}
                onChange={(e) => setNotificationsEnabled(e.target.checked)}
              />
            }
            label="Enable Email Notifications"
          />
        </Grid>

        {/* Theme Selection */}
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Theme</InputLabel>
            <Select value={theme} onChange={(e) => setTheme(e.target.value)}>
              <MenuItem value="light">Light</MenuItem>
              <MenuItem value="dark">Dark</MenuItem>
              <MenuItem value="system">System Default</MenuItem>
            </Select>
          </FormControl>
        </Grid>

        {/* Language Selection */}
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Language</InputLabel>
            <Select value={language} onChange={(e) => setLanguage(e.target.value)}>
              <MenuItem value="en">English</MenuItem>
              <MenuItem value="es">Spanish</MenuItem>
              <MenuItem value="fr">French</MenuItem>
              <MenuItem value="de">German</MenuItem>
            </Select>
          </FormControl>
        </Grid>

        {/* Incident Retention Period */}
        <Grid item xs={12} md={6}>
          <Typography gutterBottom>Incident Retention Period (days)</Typography>
          <TextField
            type="number"
            value={incidentRetention}
            onChange={(e) => setIncidentRetention(Number(e.target.value))}
            fullWidth
            inputProps={{ min: 1 }}
          />
        </Grid>

        {/* Response Delay */}
        <Grid item xs={12} md={6}>
          <Typography gutterBottom>Response Delay (seconds)</Typography>
          <TextField
            type="number"
            value={responseDelay}
            onChange={(e) => setResponseDelay(Number(e.target.value))}
            fullWidth
            inputProps={{ min: 1 }}
          />
        </Grid>
      </Grid>

      {/* Save and Reset Buttons */}
      <Box sx={{ marginTop: "2rem", textAlign: "center" }}>
        {loading ? (
          <CircularProgress />
        ) : (
          <>
            <Button
              variant="contained"
              color="primary"
              onClick={saveSettings}
              sx={{ marginRight: "1rem" }}
            >
              Save Settings
            </Button>
            <Button variant="outlined" color="secondary" onClick={resetSettings}>
              Reset to Default
            </Button>
          </>
        )}
      </Box>

      {/* Snackbar Notification */}
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

export default Settings;
