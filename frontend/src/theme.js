import { createTheme } from '@mui/material/styles';

const theme = createTheme({
  palette: {
    mode: 'light', // Dynamically switch to 'dark' for dark mode
    primary: {
      main: '#007BFF', // Primary color
      light: '#66B2FF', // Lighter shade for hover states
      dark: '#0056b3', // Darker shade for contrast
      contrastText: '#FFFFFF', // Text color for buttons, etc.
    },
    secondary: {
      main: '#6C757D', // Secondary color
      light: '#A6AAB0', // Lighter shade for hover states
      dark: '#495057', // Darker shade for contrast
      contrastText: '#FFFFFF',
    },
    background: {
      default: '#F8F9FA', // Background for the app
      paper: '#FFFFFF', // Background for cards, dialogs
    },
    text: {
      primary: '#212529', // Main text color
      secondary: '#6C757D', // Secondary text color
      disabled: '#ADB5BD', // Disabled text color
    },
  },
  typography: {
    fontFamily: '"Roboto", "Arial", sans-serif', // Font stack
    h1: {
      fontSize: '2.5rem',
      fontWeight: 700,
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
    },
    h3: {
      fontSize: '1.75rem',
      fontWeight: 600,
    },
    body1: {
      fontSize: '1rem',
      fontWeight: 400,
    },
    body2: {
      fontSize: '0.875rem',
      fontWeight: 400,
    },
    button: {
      textTransform: 'none', // Keeps button text in sentence case
    },
  },
  shape: {
    borderRadius: 8, // Rounded corners for components
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '10px 20px',
          fontWeight: 'bold',
        },
        containedPrimary: {
          backgroundColor: '#007BFF',
          color: '#FFFFFF',
          '&:hover': {
            backgroundColor: '#0056b3',
          },
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#007BFF',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          boxShadow: '0px 4px 10px rgba(0, 0, 0, 0.1)',
        },
      },
    },
  },
});

export default theme;
