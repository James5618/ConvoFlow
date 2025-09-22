import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import {
  Box,
  Container,
  Paper,
  Snackbar,
  TextField,
  Button,
  Typography,
  List,
  ListItem,
  ListItemText,
  AppBar,
  Toolbar,
  Drawer,
  IconButton,
  Alert,
  Chip,
  Divider,
  Tabs,
  Tab,
  Badge
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import MenuIcon from '@mui/icons-material/Menu';
import LockIcon from '@mui/icons-material/Lock';
import LogoutIcon from '@mui/icons-material/Logout';
import GroupIcon from '@mui/icons-material/Group';
import MessageIcon from '@mui/icons-material/Message';
import ChannelIcon from '@mui/icons-material/Tag';
import VideoCallIcon from '@mui/icons-material/VideoCall';
import CameraTest from './CameraTest';
import SettingsIcon from '@mui/icons-material/Settings';
import { roomsAPI, conversationsAPI } from '../utils/api';
import { encryptMessage, decryptMessage, clearEncryptionKey } from '../utils/encryption';
import SecureWebRTCService from '../services/SecureWebRTCService';
import VideoCallContainer from './video/VideoCallContainer';
import ServerList from './ServerList';
import ConversationsList from './ConversationsList';
import SettingsDialog from './SettingsDialog';

const ChatApp = ({ user, onLogout }) => {
  // Core state
  const [socket, setSocket] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState(0); // 0: Servers, 1: Direct Messages, 2: Rooms (legacy)
  
  // Room persistence state
  const [currentRoomId, setCurrentRoomId] = useState(null);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const currentRoomRef = useRef(null);
  
  // Chat state
  const [currentRoom, setCurrentRoom] = useState(null);
  const [selectedServer, setSelectedServer] = useState(null);
  const [selectedChannel, setSelectedChannel] = useState(null);
  const [selectedConversation, setSelectedConversation] = useState(null);
  const [messages, setMessages] = useState([]);
  const [privateMessages, setPrivateMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  
  // User persistence state
  const [roomUsers, setRoomUsers] = useState([]);
  const [onlineUsers, setOnlineUsers] = useState([]);
  
  // Video call state
  const [videoCall, setVideoCall] = useState(null);
  const [webrtcService] = useState(() => new SecureWebRTCService());
  
  // Settings
  const [settingsOpen, setSettingsOpen] = useState(false);
  // Notifications for voice channel join/leave
  const [snackOpen, setSnackOpen] = useState(false);
  const [snackMessage, setSnackMessage] = useState('');
  
  // Message scrolling refs and state
  const messagesContainerRef = useRef(null);
  const messagesEndRef = useRef(null);
  const [userHasScrolledUp, setUserHasScrolledUp] = useState(false);
  const lastMessageCountRef = useRef(0);

  useEffect(() => {
    // Get auth token for Socket.IO authentication
    const token = localStorage.getItem('authToken');
    
    // Initialize Socket.IO connection with enhanced stability settings and authentication
    const forceWs = process.env.REACT_APP_FORCE_WEBSOCKET === 'true';
    const transports = forceWs ? ['websocket'] : ['websocket', 'polling'];

    const newSocket = io('http://localhost:3001', {
      withCredentials: true,
      autoConnect: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      maxReconnectionAttempts: 5,
      timeout: 20000,
      pingTimeout: 60000,
      pingInterval: 25000,
      // Transport selection controlled by REACT_APP_FORCE_WEBSOCKET
      transports,
      path: '/socket.io',
      auth: { token }
    });

    setSocket(newSocket);

    newSocket.on('connect', () => {
      console.log('✅ Connected to server successfully');
      setError('');
    });

    newSocket.on('disconnect', (reason) => {
      console.log('❌ Disconnected from server:', reason);
      if (reason === 'io server disconnect') {
        // The disconnection was initiated by the server, you need to reconnect manually
        newSocket.connect();
      }
      setError('Connection lost. Attempting to reconnect...');
    });

    newSocket.on('connect_error', (error) => {
      console.error('❌ Socket.IO connection error:', error);
      console.log('Token being used:', token ? 'Token present' : 'No token');
      if (error.message.includes('Authentication error')) {
        setError('Authentication failed. Please log in again.');
        // Clear invalid token
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        // Redirect to login might be needed here
      } else {
        setError(`Failed to connect to server: ${error.message}`);
      }
    });

    // Handle reconnection events
    newSocket.on('reconnect', (attemptNumber) => {
      console.log('Reconnected to server after', attemptNumber, 'attempts');
      setError(''); // Clear connection errors
      setReconnectAttempts(prev => prev + 1);
      
      // Rejoin current room after reconnection
      if (currentRoomRef.current) {
        console.log('Rejoining room after reconnection:', currentRoomRef.current);
        newSocket.emit('join-room', currentRoomRef.current);
      }
    });

    newSocket.on('reconnect_error', (error) => {
      console.error('Reconnection failed:', error);
      setError('Reconnection failed. Please refresh the page.');
    });

    // FIXED: Message handling for real-time updates
    const handleNewMessage = (messageData) => {
      console.log('=== NEW MESSAGE RECEIVED ===');
      console.log('Message data:', messageData);
      console.log('Current room:', currentRoom);
      console.log('CurrentRoomRef.current:', currentRoomRef.current);
      
      // Get current room ID from multiple sources
      const currentRoomId = currentRoomRef.current || 
                           (currentRoom && currentRoom.id) || 
                           null;
      
      console.log('Room matching:', {
        currentRoomId,
        messageRoomId: messageData.room_id,
        match: currentRoomId === messageData.room_id
      });
      
      // Only add message if it's for the current room
      if (currentRoomId === messageData.room_id) {
        console.log('✅ Message is for current room, processing...');
        
        try {
          const decryptedContent = decryptMessage(messageData.encrypted_content, messageData.room_id);
          
          setMessages(prevMessages => {
            // Check for duplicates
            const isDuplicate = prevMessages.some(msg => msg.id === messageData.id);
            if (isDuplicate) {
              console.log('⚠️ Duplicate message, skipping');
              return prevMessages;
            }
            
            const newMessage = {
              ...messageData,
              decrypted_content: decryptedContent
            };
            
            console.log('📩 Adding new message:', newMessage);
            const updatedMessages = [...prevMessages, newMessage];
            console.log('� Total messages now:', updatedMessages.length);
            
            return updatedMessages;
          });
        } catch (error) {
          console.error('Error processing message:', error);
        }
      } else {
        console.log('❌ Message not for current room, ignoring');
      }
    };
    
    // Handle message sent confirmation (for sender's immediate feedback)
    const handleMessageSent = (messageData) => {
      console.log('=== MESSAGE SENT CONFIRMATION ===');
      handleNewMessage(messageData); // Use same handler
    };
    
    newSocket.on('new-message', handleNewMessage);
    newSocket.on('message-sent', handleMessageSent);

    // Private message handlers
    newSocket.on('new-private-message', (messageData) => {
      if (selectedConversation && 
          ((messageData.sender_id === selectedConversation.other_user_id && messageData.recipient_id === user.id) ||
           (messageData.sender_id === user.id && messageData.recipient_id === selectedConversation.other_user_id))) {
        const conversationKey = `dm_${Math.min(messageData.sender_id, messageData.recipient_id)}_${Math.max(messageData.sender_id, messageData.recipient_id)}`;
        const decryptedContent = decryptMessage(messageData.encrypted_content, conversationKey);
        setPrivateMessages(prev => [...prev, {
          ...messageData,
          decrypted_content: decryptedContent
        }]);
      }
    });

    newSocket.on('private-message-sent', (messageData) => {
      // Handle sent message confirmation
      if (selectedConversation && messageData.recipient_id === selectedConversation.other_user_id) {
        const conversationKey = `dm_${Math.min(user.id, selectedConversation.other_user_id)}_${Math.max(user.id, selectedConversation.other_user_id)}`;
        const decryptedContent = decryptMessage(messageData.encrypted_content, conversationKey);
        setPrivateMessages(prev => [...prev, {
          ...messageData,
          decrypted_content: decryptedContent
        }]);
      }
    });

    // Error handling
    newSocket.on('message-error', (errorData) => {
      console.error('Message error:', errorData);
      setError(errorData.error || 'Failed to send message');
    });

    // User presence events
    newSocket.on('user-joined-room', (userData) => {
      console.log('User joined room:', userData);
      setRoomUsers(prev => {
        if (prev.find(u => u.id === userData.id)) {
          return prev; // User already in list
        }
        return [...prev, userData];
      });
    });

    newSocket.on('user-left-room', (userData) => {
      console.log('User left room:', userData);
      setRoomUsers(prev => prev.filter(u => u.id !== userData.id));
    });

    // Voice channel notifications
    newSocket.on('voice-user-joined', (data) => {
      console.log('Voice user joined:', data);
      setSnackMessage(`${data.username} joined voice`);
      setSnackOpen(true);
    });

    newSocket.on('voice-user-left', (data) => {
      console.log('Voice user left:', data);
      setSnackMessage(`${data.username} left voice`);
      setSnackOpen(true);
    });

    newSocket.on('room-users-list', (usersList) => {
      console.log('Room users list received:', usersList);
      setRoomUsers(usersList);
    });

    newSocket.on('online-users', (usersList) => {
      console.log('Online users list received:', usersList);
      setOnlineUsers(usersList);
    });

    // WebRTC event handlers
    newSocket.on('webrtc-offer', (data) => {
      webrtcService.handleOffer(data);
    });

    newSocket.on('webrtc-answer', (data) => {
      webrtcService.handleAnswer(data);
    });

    newSocket.on('webrtc-ice-candidate', (data) => {
      webrtcService.handleIceCandidate(data);
    });

    return () => {
      console.log('=== CLEANING UP SOCKET ===');
      if (currentRoomRef.current) {
        console.log('Leaving room on cleanup:', currentRoomRef.current);
        newSocket.emit('leave-room', currentRoomRef.current);
      }
      
      // Remove event listeners
      newSocket.off('new-message', handleNewMessage);
      newSocket.off('message-sent', handleMessageSent);
  newSocket.off('voice-user-joined');
  newSocket.off('voice-user-left');
      
      newSocket.disconnect();
      console.log('Socket disconnected and cleaned up');
    };
  }, [user.id, currentRoom, selectedConversation, webrtcService]);

  const handleSnackClose = () => {
    setSnackOpen(false);
    setSnackMessage('');
  };

  // Auto-scroll effect for new messages
  useEffect(() => {
    const currentMessages = currentRoom ? messages : privateMessages;
    const messageCount = currentMessages.length;
    
    if (messageCount > lastMessageCountRef.current) {
      // New message(s) added, scroll to bottom
      setTimeout(() => scrollToBottom(), 100); // Small delay to ensure DOM update
    }
    
    lastMessageCountRef.current = messageCount;
  }, [messages, privateMessages, currentRoom]);

  const selectRoom = async (room) => {
    console.log('=== SELECTING ROOM ===');
    console.log('New room:', room);
    console.log('Previous room:', currentRoom);
    
    if (currentRoom) {
      console.log('Leaving previous room:', currentRoom.id);
      socket?.emit('leave-room', currentRoom.id);
    }
    
    setCurrentRoom(room);
    setCurrentRoomId(room.id);
    currentRoomRef.current = room.id;
    console.log('Updated currentRoomRef to:', currentRoomRef.current);
    
    setMessages([]);
    setSelectedChannel(null);
    setSelectedConversation(null);
    setPrivateMessages([]);
    setRoomUsers([]); // Clear previous room users
    
    if (socket) {
      console.log('Joining room:', room.id);
      socket.emit('join-room', room.id);
      // Request current users in the room
      socket.emit('get-room-users', room.id);
    } else {
      console.log('❌ No socket connection available');
    }

    try {
      console.log('Loading messages for room:', room.id);
      const response = await roomsAPI.getMessages(room.id);
      const decryptedMessages = response.data.map(msg => ({
        ...msg,
        decrypted_content: decryptMessage(msg.encrypted_content, room.id)
      }));
      console.log('Loaded', decryptedMessages.length, 'historical messages');
      setMessages(decryptedMessages);
      // Reset scroll state and scroll to bottom for new room
      setUserHasScrolledUp(false);
      setTimeout(() => scrollToBottom(true), 200);
    } catch (error) {
      console.error('Failed to load messages:', error);
      setError('Failed to load messages');
    }
  };

  const selectChannel = async (channel) => {
    if (currentRoom) {
      socket?.emit('leave-room', currentRoom.id);
    }
    
    setCurrentRoom(channel);
    setCurrentRoomId(channel.id);
    currentRoomRef.current = channel.id;
    setSelectedChannel(channel);
    setMessages([]);
    setSelectedConversation(null);
    setPrivateMessages([]);
    setRoomUsers([]); // Clear previous room users
    
    socket?.emit('join-room', channel.id);
    // Request current users in the channel
    socket?.emit('get-room-users', channel.id);

    try {
      const response = await roomsAPI.getMessages(channel.id);
      const decryptedMessages = response.data.map(msg => ({
        ...msg,
        decrypted_content: decryptMessage(msg.encrypted_content, channel.id)
      }));
      setMessages(decryptedMessages);
      // Reset scroll state and scroll to bottom for new channel
      setUserHasScrolledUp(false);
      setTimeout(() => scrollToBottom(true), 200);
    } catch (error) {
      setError('Failed to load messages');
    }
  };

  const selectConversation = async (conversation) => {
    if (currentRoom) {
      socket?.emit('leave-room', currentRoom.id);
    }
    
    setSelectedConversation(conversation);
    setCurrentRoom(null);
    setCurrentRoomId(null);
    currentRoomRef.current = null;
    setSelectedChannel(null);
    setMessages([]);
    setPrivateMessages([]);

    try {
      const conversationKey = `dm_${Math.min(user.id, conversation.other_user_id)}_${Math.max(user.id, conversation.other_user_id)}`;
      const response = await conversationsAPI.getMessages(conversation.id);
      const decryptedMessages = response.data.map(msg => ({
        ...msg,
        decrypted_content: decryptMessage(msg.encrypted_content, conversationKey)
      }));
      setPrivateMessages(decryptedMessages);
      // Reset scroll state and scroll to bottom for new conversation
      setUserHasScrolledUp(false);
      setTimeout(() => scrollToBottom(true), 200);
    } catch (error) {
      setError('Failed to load conversation');
    }
  };

  const sendMessage = () => {
    if (!newMessage.trim()) {
      setError('Please enter a message');
      return;
    }
    
    if (!socket) {
      setError('Not connected to server. Please refresh the page.');
      return;
    }

    // Validate message length (4000 chars for original message, accounting for encryption overhead)
    if (newMessage.length > 4000) {
      setError('Message too long (maximum 4000 characters)');
      return;
    }

    try {
      if (selectedConversation) {
        // Send private message
        const conversationKey = `dm_${Math.min(user.id, selectedConversation.other_user_id)}_${Math.max(user.id, selectedConversation.other_user_id)}`;
        
        let encryptedContent;
        try {
          encryptedContent = encryptMessage(newMessage, conversationKey);
        } catch (encError) {
          console.error('Encryption error:', encError);
          setError('Failed to encrypt message. Please try again.');
          return;
        }
        
        // Additional check for encrypted content length
        if (encryptedContent.length > 5000) {
          setError('Message too long after encryption');
          return;
        }
        
        console.log('Sending private message to:', selectedConversation.other_user_id);
        socket.emit('send-private-message', {
          recipientId: selectedConversation.other_user_id,
          encryptedMessage: encryptedContent
        });
      } else if (currentRoom) {
        // Send room/channel message
        let encryptedContent;
        try {
          encryptedContent = encryptMessage(newMessage, currentRoom.id);
        } catch (encError) {
          console.error('Encryption error:', encError);
          setError('Failed to encrypt message. Please try again.');
          return;
        }
        
        // Additional check for encrypted content length
        if (encryptedContent.length > 5000) {
          setError('Message too long after encryption');
          return;
        }
        
        console.log('Sending message to room:', currentRoom.id);
        socket.emit('send-message', {
          roomId: currentRoom.id,
          encryptedMessage: encryptedContent
        });
      } else {
        setError('Please select a channel or conversation first');
        return;
      }
      
      setNewMessage('');
      setError(''); // Clear any previous errors
    } catch (error) {
      console.error('Send message error:', error);
      setError(`Failed to send message: ${error.message || 'Unknown error'}`);
    }
  };

  // Auto-scroll functions
  const scrollToBottom = (force = false) => {
    if (messagesEndRef.current && (!userHasScrolledUp || force)) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleScroll = () => {
    if (messagesContainerRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = messagesContainerRef.current;
      const isScrolledToBottom = scrollHeight - scrollTop <= clientHeight + 50; // 50px tolerance
      setUserHasScrolledUp(!isScrolledToBottom);
    }
  };

  const handleLogout = () => {
    clearEncryptionKey();
    if (socket) {
      socket.disconnect();
    }
    onLogout();
  };

  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
    setCurrentRoom(null);
    setCurrentRoomId(null);
    currentRoomRef.current = null;
    setSelectedChannel(null);
    setSelectedConversation(null);
    setMessages([]);
    setPrivateMessages([]);
    setSelectedServer(null);
  };

  const currentMessages = selectedConversation ? privateMessages : messages;

  return (
    <Box sx={{ display: 'flex', height: '100vh' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={() => setDrawerOpen(!drawerOpen)}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            ConvoFlow - {user.username}
            {reconnectAttempts > 0 && (
              <Chip 
                label={`Reconnected (${reconnectAttempts})`} 
                size="small" 
                color="success" 
                sx={{ ml: 2 }} 
              />
            )}
          </Typography>
          <IconButton color="inherit" onClick={() => setSettingsOpen(true)}>
            <SettingsIcon />
          </IconButton>
          <IconButton color="inherit" onClick={handleLogout}>
            <LogoutIcon />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Drawer
        variant="persistent"
        open={drawerOpen}
        sx={{
          width: 300,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: 300,
            boxSizing: 'border-box',
            mt: 8,
          },
        }}
      >
        <Tabs value={activeTab} onChange={handleTabChange} variant="fullWidth">
          <Tab icon={<GroupIcon />} label="Servers" />
          <Tab icon={<MessageIcon />} label="Direct Messages" />
        </Tabs>
        
        <Divider />
        
        {activeTab === 0 && (
          <ServerList 
            onServerSelect={setSelectedServer}
            onChannelSelect={selectChannel}
            selectedServer={selectedServer}
            selectedChannel={selectedChannel}
          />
        )}
        
        {activeTab === 1 && (
          <ConversationsList 
            onConversationSelect={selectConversation}
            selectedConversation={selectedConversation}
          />
        )}
      </Drawer>

      <Container 
        maxWidth={false} 
        sx={{ 
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
          ml: drawerOpen ? '300px' : 0,
          mt: 8,
          transition: 'margin 0.3s',
          height: 'calc(100vh - 64px)',
          overflow: 'hidden'
        }}
      >
        {error && (
          <Alert severity="error" sx={{ mb: 1 }}>
            {error}
          </Alert>
        )}

        {!currentRoom && !selectedConversation && (
          <Box sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center', 
            height: '100%',
            flexDirection: 'column' 
          }}>
            <LockIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              Select a channel or conversation to start chatting
            </Typography>
          </Box>
        )}

        {(currentRoom || selectedConversation) && (
          <>
            <Paper elevation={1} sx={{ p: 2, mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h6">
                  {selectedConversation 
                    ? `Direct Message: ${selectedConversation.other_username}`
                    : currentRoom?.name || 'Unknown Room'
                  }
                </Typography>
                {currentRoom && roomUsers.length > 0 && (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <GroupIcon color="action" />
                    <Badge badgeContent={roomUsers.length} color="primary">
                      <Typography variant="body2" color="text.secondary">
                        Users Online
                      </Typography>
                    </Badge>
                  </Box>
                )}
              </Box>
              {currentRoom && roomUsers.length > 0 && (
                <Box sx={{ mt: 1, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                  {roomUsers.map((user) => (
                    <Chip 
                      key={user.id} 
                      label={user.username} 
                      size="small" 
                      variant="outlined"
                      color={user.id === user.id ? "primary" : "default"}
                    />
                  ))}
                </Box>
              )}
            </Paper>

            <Paper 
              ref={messagesContainerRef}
              onScroll={handleScroll}
              elevation={1} 
              sx={{ 
                flexGrow: 1, 
                p: 2, 
                mb: 2, 
                overflow: 'auto',
                display: 'flex',
                flexDirection: 'column'
              }}
            >
              <List sx={{ flexGrow: 1 }}>
                {currentMessages.map((message) => (
                  <ListItem key={message.id} alignItems="flex-start">
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2" color="primary">
                            {message.username}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(message.timestamp).toLocaleTimeString()}
                          </Typography>
                        </Box>
                      }
                      secondary={
                        <Typography variant="body1" sx={{ mt: 0.5 }}>
                          {message.decrypted_content}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
                {/* Invisible element to scroll to */}
                <div ref={messagesEndRef} />
              </List>
            </Paper>

            <Paper elevation={1} sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <TextField
                  fullWidth
                  variant="outlined"
                  placeholder="Type your message..."
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  multiline
                  maxRows={4}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      sendMessage();
                    }
                  }}
                />
                <Button
                  variant="contained"
                  onClick={sendMessage}
                  disabled={!newMessage.trim()}
                  startIcon={<SendIcon />}
                >
                  Send
                </Button>
                <Button
                  variant="outlined"
                  onClick={() => {
                    console.log('Video Call button clicked');
                    console.log('Current room:', currentRoom);
                    console.log('Selected conversation:', selectedConversation);
                    setVideoCall(currentRoom || selectedConversation);
                  }}
                  disabled={!currentRoom && !selectedConversation}
                  startIcon={<VideoCallIcon />}
                  sx={{ ml: 1, bgcolor: 'lightblue' }} // Temporary blue background to make it visible
                >
                  📹 Video Call
                </Button>
              </Box>
            </Paper>
          </>
        )}

        {videoCall && (
          <VideoCallContainer
            webrtcService={webrtcService}
            socket={socket}
            currentUser={user}
            roomId={currentRoom?.id}
          />
        )}
      </Container>

      <SettingsDialog 
        open={settingsOpen} 
        onClose={() => setSettingsOpen(false)} 
      />
      <Snackbar
        open={snackOpen}
        autoHideDuration={3000}
        message={snackMessage}
        onClose={handleSnackClose}
      />
    </Box>
  );
};

export default ChatApp;
