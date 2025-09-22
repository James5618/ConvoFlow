import React, { useState, useEffect } from 'react';
import {
  Box,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListItemIcon,
  Typography,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Chip,
  Divider,
  Tooltip,
  FormControlLabel,
  Switch,
  Alert
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import GroupIcon from '@mui/icons-material/Group';
import SettingsIcon from '@mui/icons-material/Settings';
import CopyIcon from '@mui/icons-material/ContentCopy';
import JoinIcon from '@mui/icons-material/Login';
import ChannelIcon from '@mui/icons-material/Tag';
import { serversAPI, authAPI } from '../utils/api';

const ServerList = ({ onServerSelect, onChannelSelect, selectedServer, selectedChannel }) => {
  const [servers, setServers] = useState([]);
  const [channels, setChannels] = useState([]);
  const [voiceChannels, setVoiceChannels] = useState([]);
  const [membersDialogOpen, setMembersDialogOpen] = useState(false);
  const [serverMembers, setServerMembers] = useState([]);
  const [createServerDialog, setCreateServerDialog] = useState(false);
  const [joinServerDialog, setJoinServerDialog] = useState(false);
  const [createChannelDialog, setCreateChannelDialog] = useState(false);
  const [newServerName, setNewServerName] = useState('');
  const [newServerDescription, setNewServerDescription] = useState('');
  const [newServerPublic, setNewServerPublic] = useState(false);
  const [inviteCode, setInviteCode] = useState('');
  const [newChannelName, setNewChannelName] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [reauthAttempted, setReauthAttempted] = useState(false);
  const [reauthDialogOpen, setReauthDialogOpen] = useState(false);
  const [reauthUsername, setReauthUsername] = useState('');
  const [reauthPassword, setReauthPassword] = useState('');

  useEffect(() => {
    loadServers();
  }, []);

  useEffect(() => {
    if (selectedServer) {
      loadChannels(selectedServer.id);
      loadVoiceChannels(selectedServer.id);
    }
  }, [selectedServer]);

  const loadServers = async () => {
    try {
      // Quick health check before calling servers endpoint
      try {
        const health = await fetch((process.env.REACT_APP_API_URL || 'http://localhost:3001') + '/health');
        if (!health.ok) {
          throw new Error('API health check failed: ' + health.status);
        }
      } catch (e) {
        console.error('API health check failed:', e);
        setError('Network error: cannot reach API server');
        return;
      }

      const response = await serversAPI.getServers();
      console.log('Loaded servers response:', response);
      setServers(response.data);
    } catch (error) {
      // Detailed logging for diagnostics
      console.error('Failed to load servers:', error);
      console.log('Auth token present?', !!localStorage.getItem('authToken'));
      try {
        console.error('Axios error config:', error.config);
        console.error('Axios error response:', error.response);
      } catch (e) {}

      const status = error.response?.status;
      const msg = error.response?.data?.error || error.message || 'Unknown error';
      if (status === 401 || status === 403) {
        // Try to re-authenticate once using stored username (prompt for password)
        const storedUser = (() => {
          try { return JSON.parse(localStorage.getItem('user') || 'null'); } catch (e) { return null; }
        })();
        if (storedUser && storedUser.username && !reauthAttempted) {
          // Open a modal to ask for the password and attempt re-login
          setReauthAttempted(true);
          setReauthUsername(storedUser.username);
          setReauthPassword('');
          setReauthDialogOpen(true);
          return; // wait for user to submit via modal
        }

        // If no stored user or reauth already attempted, clear and redirect
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        window.location.href = '/login';
        setError('Unauthorized. Redirecting to login.');
      } else if (status >= 500) {
        setError(`Server error when loading servers: ${msg}`);
      } else if (error.message && error.message.includes('Network Error')) {
        setError('Network error: cannot reach API server');
      } else {
        setError(`Failed to load servers: ${msg}`);
      }
    }
  };

  const loadChannels = async (serverId) => {
    try {
      const response = await serversAPI.getChannels(serverId);
      console.log('Loaded channels response for', serverId, response);
      setChannels(response.data);
    } catch (error) {
      console.error('Failed to load channels:', error);
      const status = error.response?.status;
      const msg = error.response?.data?.error || error.message || 'Unknown error';
      if (status === 403) {
        setError('Access denied to channels for this server');
      } else if (status === 401) {
        setError('Unauthorized. Please log in again.');
      } else if (error.message && error.message.includes('Network Error')) {
        setError('Network error: cannot reach API server');
      } else {
        setError(`Failed to load channels: ${msg}`);
      }
    }
  };

  const loadVoiceChannels = async (serverId) => {
    try {
      const response = await serversAPI.getChannels(serverId);
      // Filter voice channels (is_voice flag)
      const voice = response.data.filter(c => c.is_voice);
      setVoiceChannels(voice);
    } catch (error) {
      console.error('Failed to load voice channels:', error);
    }
  };

  const loadMembers = async (serverId) => {
    try {
      const response = await serversAPI.getMembers(serverId);
      setServerMembers(response.data);
    } catch (error) {
      console.error('Failed to load members:', error);
      setError(error.response?.data?.error || 'Failed to load members');
    }
  };

  const createServer = async () => {
    if (!newServerName.trim()) return;

    try {
      const response = await serversAPI.createServer({
        name: newServerName,
        description: newServerDescription,
        isPublic: newServerPublic
      });
      
      setServers(prev => [...prev, response.data]);
      setNewServerName('');
      setNewServerDescription('');
      setNewServerPublic(false);
      setCreateServerDialog(false);
      setSuccess('Server created successfully!');
      
      // Auto-select the new server
      onServerSelect(response.data);
    } catch (error) {
      setError('Failed to create server');
    }
  };

  const joinServer = async () => {
    if (!inviteCode.trim()) return;

    try {
      const response = await serversAPI.joinServer(inviteCode);
      setInviteCode('');
      setJoinServerDialog(false);
      setSuccess('Successfully joined server!');
      loadServers(); // Reload servers list
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to join server');
    }
  };

  const createChannel = async () => {
    if (!newChannelName.trim() || !selectedServer) return;

    try {
      const response = await serversAPI.createChannel(selectedServer.id, newChannelName);
      setChannels(prev => [...prev, response.data]);
      setNewChannelName('');
      setCreateChannelDialog(false);
      setSuccess('Channel created successfully!');
      
      // Auto-select the new channel
      onChannelSelect(response.data);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create channel');
    }
  };

  const createVoiceChannel = async () => {
    if (!newChannelName.trim() || !selectedServer) return;
    try {
      const response = await serversAPI.createVoiceChannel(selectedServer.id, newChannelName);
      setVoiceChannels(prev => [...prev, response.data]);
      setNewChannelName('');
      setCreateChannelDialog(false);
      setSuccess('Voice channel created successfully!');
      onChannelSelect(response.data);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create voice channel');
    }
  };

  const copyInviteCode = (code) => {
    navigator.clipboard.writeText(code);
    setSuccess('Invite code copied to clipboard!');
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {error && (
        <Alert severity="error" onClose={() => setError('')} sx={{ m: 1 }}>
          {error}
        </Alert>
      )}
      
      {success && (
        <Alert severity="success" onClose={() => setSuccess('')} sx={{ m: 1 }}>
          {success}
        </Alert>
      )}

      {/* Server Actions */}
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Typography variant="h6" gutterBottom>
          Servers
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Create Server">
            <IconButton 
              size="small" 
              onClick={() => setCreateServerDialog(true)}
              color="primary"
            >
              <AddIcon />
            </IconButton>
          </Tooltip>
          <Tooltip title="Join Server">
            <IconButton 
              size="small" 
              onClick={() => setJoinServerDialog(true)}
              color="secondary"
            >
              <JoinIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Servers List */}
      <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
        <List dense>
          {servers.map((server) => (
            <ListItem key={server.id} disablePadding>
              <ListItemButton
                selected={selectedServer?.id === server.id}
                onClick={() => onServerSelect(server)}
              >
                <ListItemIcon>
                  <GroupIcon />
                </ListItemIcon>
                <ListItemText 
                  primary={server.name}
                  secondary={server.description}
                />
                {server.invite_code && (
                  <Tooltip title="Copy Invite Code">
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyInviteCode(server.invite_code);
                      }}
                    >
                      <CopyIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                )}
              </ListItemButton>
            </ListItem>
          ))}
        </List>

        {/* Channels List */}
        {selectedServer && (
          <>
            <Divider />
            <Box sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="subtitle1">
                  Channels in {selectedServer.name}
                </Typography>
                <Tooltip title="Create Channel">
                  <IconButton 
                    size="small" 
                    onClick={() => setCreateChannelDialog(true)}
                    color="primary"
                  >
                    <AddIcon />
                  </IconButton>
                </Tooltip>
                  <Tooltip title="Manage Members">
                    <IconButton size="small" onClick={() => { setMembersDialogOpen(true); loadMembers(selectedServer.id); }}>
                      <SettingsIcon />
                    </IconButton>
                  </Tooltip>
              </Box>
              
              <List dense>
                {channels.map((channel) => (
                  <ListItem key={channel.id} disablePadding>
                    <ListItemButton
                      selected={selectedChannel?.id === channel.id}
                      onClick={() => onChannelSelect(channel)}
                      sx={{ pl: 3 }}
                    >
                      <ListItemIcon>
                        <ChannelIcon />
                      </ListItemIcon>
                      <ListItemText primary={`# ${channel.name}`} />
                    </ListItemButton>
                  </ListItem>
                ))}
              </List>

              {/* Voice Channels */}
              {voiceChannels.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2">Voice Channels</Typography>
                  <List dense>
                    {voiceChannels.map((vc) => (
                      <ListItem key={vc.id} disablePadding>
                        <ListItemButton sx={{ pl: 3 }} onClick={async () => {
                          try {
                            await serversAPI.joinVoiceChannel(vc.id);
                            setSuccess(`Joined voice channel ${vc.name}`);
                            // Client should trigger socket join/RTCPeer logic elsewhere
                          } catch (e) {
                            setError(e.response?.data?.error || 'Failed to join voice channel');
                          }
                        }}>
                          <ListItemIcon>
                            <ChannelIcon />
                          </ListItemIcon>
                          <ListItemText primary={`🔊 ${vc.name}`} />
                        </ListItemButton>
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}
            </Box>
          </>
        )}
      </Box>

      {/* Create Server Dialog */}
      <Dialog open={createServerDialog} onClose={() => setCreateServerDialog(false)}>
        <DialogTitle>Create New Server</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Server Name"
            fullWidth
            variant="outlined"
            value={newServerName}
            onChange={(e) => setNewServerName(e.target.value)}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Description (optional)"
            fullWidth
            variant="outlined"
            multiline
            rows={2}
            value={newServerDescription}
            onChange={(e) => setNewServerDescription(e.target.value)}
            sx={{ mb: 2 }}
          />
          <FormControlLabel
            control={
              <Switch
                checked={newServerPublic}
                onChange={(e) => setNewServerPublic(e.target.checked)}
              />
            }
            label="Public Server"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateServerDialog(false)}>Cancel</Button>
          <Button onClick={createServer} variant="contained">Create</Button>
        </DialogActions>
      </Dialog>

      {/* Join Server Dialog */}
      <Dialog open={joinServerDialog} onClose={() => setJoinServerDialog(false)}>
        <DialogTitle>Join Server</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Invite Code"
            fullWidth
            variant="outlined"
            value={inviteCode}
            onChange={(e) => setInviteCode(e.target.value)}
            placeholder="Enter server invite code"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setJoinServerDialog(false)}>Cancel</Button>
          <Button onClick={joinServer} variant="contained">Join</Button>
        </DialogActions>
      </Dialog>

      {/* Create Channel Dialog */}
      <Dialog open={createChannelDialog} onClose={() => setCreateChannelDialog(false)}>
        <DialogTitle>Create New Channel</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Channel Name"
            fullWidth
            variant="outlined"
            value={newChannelName}
            onChange={(e) => setNewChannelName(e.target.value)}
            placeholder="general"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateChannelDialog(false)}>Cancel</Button>
          <Button onClick={createChannel} variant="contained">Create Text Channel</Button>
          <Button onClick={createVoiceChannel} variant="outlined">Create Voice Channel</Button>
        </DialogActions>
      </Dialog>

      {/* Members Dialog */}
      <Dialog open={membersDialogOpen} onClose={() => setMembersDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Server Members</DialogTitle>
        <DialogContent>
          <List>
            {serverMembers.map((m) => (
              <ListItem key={m.user_id} secondaryAction={(
                <Box>
                  <Chip label={m.role} size="small" sx={{ mr: 1 }} />
                  <Button size="small" onClick={async () => {
                    // Cycle role: member -> moderator -> admin
                    const next = m.role === 'member' ? 'moderator' : m.role === 'moderator' ? 'admin' : 'member';
                    try {
                      await serversAPI.setMemberRole(selectedServer.id, m.user_id, next);
                      setSuccess('Role updated');
                      loadMembers(selectedServer.id);
                    } catch (e) {
                      setError(e.response?.data?.error || 'Failed to update role');
                    }
                  }}>Change Role</Button>
                </Box>
              )}>
                <ListItemText primary={m.username} secondary={m.display_name} />
              </ListItem>
            ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMembersDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Re-auth Dialog (shown when token expired) */}
      <Dialog open={reauthDialogOpen} onClose={() => setReauthDialogOpen(false)}>
        <DialogTitle>Session Expired — Re-login</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 1 }}>
            Your session has expired. Please re-enter your password to continue as <strong>{reauthUsername}</strong>.
          </Typography>
          <TextField
            autoFocus
            margin="dense"
            label="Username"
            fullWidth
            variant="outlined"
            value={reauthUsername}
            onChange={(e) => setReauthUsername(e.target.value)}
            sx={{ mb: 2 }}
            disabled
          />
          <TextField
            margin="dense"
            label="Password"
            type="password"
            fullWidth
            variant="outlined"
            value={reauthPassword}
            onChange={(e) => setReauthPassword(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setReauthDialogOpen(false);
            // If user cancels, clear auth and go to login
            localStorage.removeItem('authToken');
            localStorage.removeItem('user');
            window.location.href = '/login';
          }}>Cancel</Button>
          <Button onClick={async () => {
            try {
              const loginResp = await authAPI.login({ username: reauthUsername, password: reauthPassword });
              const { token, user } = loginResp.data;
              localStorage.setItem('authToken', token);
              localStorage.setItem('user', JSON.stringify(user));
              setReauthDialogOpen(false);
              // Retry servers load once
              await loadServers();
            } catch (e) {
              console.error('Re-login failed:', e);
              setError(e.response?.data?.error || 'Re-login failed');
            }
          }} variant="contained">Re-login</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ServerList;
