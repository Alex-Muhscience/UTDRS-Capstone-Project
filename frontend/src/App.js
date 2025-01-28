import React, { useState, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Reports from './pages/Reports';
import ReportDetails from './pages/ReportDetails'; // Dynamic route for report details
import Settings from './pages/Settings';
import Profile from './pages/Profile';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

// Create App Context for global state
export const AppContext = createContext();

// Custom Hook to access App Context
export const useAppContext = () => useContext(AppContext);

const App = () => {
  // Global states
  const [darkMode, setDarkMode] = useState(false);
  const [user, setUser] = useState({ isAuthenticated: true, name: 'Admin User' });

  // Dynamic MUI Theme
  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: {
        main: '#007BFF',
      },
      secondary: {
        main: '#6C757D',
      },
      background: {
        default: darkMode ? '#303030' : '#F8F9FA',
        paper: darkMode ? '#424242' : '#FFFFFF',
      },
    },
    typography: {
      fontFamily: '"Roboto", "Arial", sans-serif',
      button: {
        textTransform: 'none',
      },
    },
  });

  return (
    <AppContext.Provider value={{ darkMode, setDarkMode, user, setUser }}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Router>
          {/* Navbar handles navigation and theme switching */}
          <Navbar />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:reportId" element={<ReportDetails />} /> {/* Dynamic Route */}
            <Route path="/settings" element={<Settings />} />
            <Route path="/profile" element={<Profile />} />
          </Routes>
        </Router>
      </ThemeProvider>
    </AppContext.Provider>
  );
};

export default App;
