import React, { useState } from 'react';
import {
  Box,
  Typography,
  Avatar,
  TextField,
  Grid,
  Card,
  CardContent,
  Button,
  Snackbar,
  Alert,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import SaveIcon from '@mui/icons-material/Save';
import CancelIcon from '@mui/icons-material/Cancel';
import UploadIcon from '@mui/icons-material/Upload';

const Profile = () => {
  const [editing, setEditing] = useState(false);
  const [profile, setProfile] = useState({
    name: 'John Doe',
    email: 'johndoe@example.com',
    phone: '+1234567890',
    bio: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
    avatar: null,
  });

  const [tempProfile, setTempProfile] = useState(profile);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [snackbarSeverity, setSnackbarSeverity] = useState('success');

  const handleEditClick = () => {
    setEditing(true);
  };

  const handleSaveClick = () => {
    setProfile(tempProfile);
    setEditing(false);
    setSnackbarMessage('Profile updated successfully!');
    setSnackbarSeverity('success');
  };

  const handleCancelClick = () => {
    setTempProfile(profile);
    setEditing(false);
    setSnackbarMessage('Changes discarded.');
    setSnackbarSeverity('info');
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setTempProfile({ ...tempProfile, [name]: value });
  };

  const handleAvatarUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        setTempProfile({ ...tempProfile, avatar: reader.result });
        setSnackbarMessage('Avatar uploaded successfully!');
        setSnackbarSeverity('success');
      };
      reader.readAsDataURL(file);
    }
  };

  const handleCloseSnackbar = () => {
    setSnackbarMessage('');
  };

  return (
    <Box sx={{ padding: '2rem' }}>
      <Typography variant="h4" gutterBottom>
        Profile Settings
      </Typography>
      <Card>
        <CardContent>
          <Grid container spacing={3} alignItems="center">
            {/* Avatar Section */}
            <Grid item xs={12} md={4} style={{ textAlign: 'center' }}>
              <Avatar
                sx={{ width: 120, height: 120, margin: 'auto' }}
                src={tempProfile.avatar || ''}
              >
                {!tempProfile.avatar && tempProfile.name[0]}
              </Avatar>
              {editing && (
                <Button
                  variant="outlined"
                  component="label"
                  sx={{ marginTop: '1rem' }}
                  startIcon={<UploadIcon />}
                >
                  Upload Avatar
                  <input
                    type="file"
                    hidden
                    accept="image/*"
                    onChange={handleAvatarUpload}
                  />
                </Button>
              )}
            </Grid>

            {/* Profile Details Section */}
            <Grid item xs={12} md={8}>
              <Grid container spacing={3}>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Name"
                    name="name"
                    value={tempProfile.name}
                    onChange={handleChange}
                    disabled={!editing}
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Email"
                    name="email"
                    value={tempProfile.email}
                    onChange={handleChange}
                    disabled={!editing}
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Phone"
                    name="phone"
                    value={tempProfile.phone}
                    onChange={handleChange}
                    disabled={!editing}
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Bio"
                    name="bio"
                    multiline
                    rows={4}
                    value={tempProfile.bio}
                    onChange={handleChange}
                    disabled={!editing}
                  />
                </Grid>
              </Grid>
            </Grid>
          </Grid>

          {/* Action Buttons */}
          <Box sx={{ textAlign: 'right', marginTop: '2rem' }}>
            {editing ? (
              <>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<SaveIcon />}
                  onClick={handleSaveClick}
                  sx={{ marginRight: '1rem' }}
                >
                  Save
                </Button>
                <Button
                  variant="outlined"
                  color="secondary"
                  startIcon={<CancelIcon />}
                  onClick={handleCancelClick}
                >
                  Cancel
                </Button>
              </>
            ) : (
              <Button
                variant="contained"
                color="primary"
                startIcon={<EditIcon />}
                onClick={handleEditClick}
              >
                Edit Profile
              </Button>
            )}
          </Box>
        </CardContent>
      </Card>

      {/* Snackbar Notifications */}
      <Snackbar
        open={!!snackbarMessage}
        autoHideDuration={3000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbarSeverity}
          sx={{ width: '100%' }}
        >
          {snackbarMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Profile;
