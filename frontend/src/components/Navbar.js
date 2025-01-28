import React, { useState } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  IconButton,
  Menu,
  MenuItem,
  useMediaQuery,
  Switch,
} from '@mui/material';
import { Link } from 'react-router-dom';
import { AccountCircle, Menu as MenuIcon, Brightness4, Brightness7 } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';

const Navbar = ({ darkMode, setDarkMode }) => {
  const [anchorEl, setAnchorEl] = useState(null);
  const [mobileAnchorEl, setMobileAnchorEl] = useState(null);
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));

  // Profile menu handlers
  const handleProfileMenuOpen = (event) => setAnchorEl(event.currentTarget);
  const handleProfileMenuClose = () => setAnchorEl(null);

  // Mobile menu handlers
  const handleMobileMenuOpen = (event) => setMobileAnchorEl(event.currentTarget);
  const handleMobileMenuClose = () => setMobileAnchorEl(null);

  const handleThemeToggle = () => setDarkMode((prev) => !prev);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static" sx={{ backgroundColor: theme.palette.primary.main }}>
        <Toolbar>
          {/* Logo and Title */}
          <Typography
            variant="h6"
            component="div"
            sx={{
              flexGrow: 1,
              display: 'flex',
              alignItems: 'center',
            }}
          >
            UTDRS
          </Typography>

          {/* Desktop Menu */}
          {!isMobile && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Button color="inherit" component={Link} to="/">
                Dashboard
              </Button>
              <Button color="inherit" component={Link} to="/reports">
                Reports
              </Button>
              <Button color="inherit" component={Link} to="/settings">
                Settings
              </Button>
              <Switch
                checked={darkMode}
                onChange={handleThemeToggle}
                icon={<Brightness4 />}
                checkedIcon={<Brightness7 />}
              />
              <IconButton
                edge="end"
                color="inherit"
                aria-controls="profile-menu"
                aria-haspopup="true"
                onClick={handleProfileMenuOpen}
              >
                <AccountCircle />
              </IconButton>
            </Box>
          )}

          {/* Mobile Menu Toggle */}
          {isMobile && (
            <IconButton
              edge="end"
              color="inherit"
              aria-label="menu"
              aria-controls="mobile-menu"
              onClick={handleMobileMenuOpen}
            >
              <MenuIcon />
            </IconButton>
          )}
        </Toolbar>
      </AppBar>

      {/* Profile Menu */}
      <Menu
        id="profile-menu"
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleProfileMenuClose}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <MenuItem onClick={handleProfileMenuClose}>Profile</MenuItem>
        <MenuItem onClick={handleProfileMenuClose}>My Account</MenuItem>
        <MenuItem onClick={handleProfileMenuClose}>Logout</MenuItem>
      </Menu>

      {/* Mobile Menu */}
      <Menu
        id="mobile-menu"
        anchorEl={mobileAnchorEl}
        open={Boolean(mobileAnchorEl)}
        onClose={handleMobileMenuClose}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <MenuItem component={Link} to="/" onClick={handleMobileMenuClose}>
          Dashboard
        </MenuItem>
        <MenuItem component={Link} to="/reports" onClick={handleMobileMenuClose}>
          Reports
        </MenuItem>
        <MenuItem component={Link} to="/settings" onClick={handleMobileMenuClose}>
          Settings
        </MenuItem>
        <MenuItem onClick={handleThemeToggle}>
          {darkMode ? 'Light Mode' : 'Dark Mode'}
        </MenuItem>
        <MenuItem onClick={handleProfileMenuOpen}>
          <AccountCircle sx={{ marginRight: '8px' }} /> Profile
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default Navbar;
