import React, { useState } from 'react';
import './App.css';
import ChatInterface from './components/ChatInterface';

function App() {
  const [messages, setMessages] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  const handleSendMessage = async (message, isImage = false, imageFile = null) => {
    const userMessage = {
      id: Date.now(),
      type: 'user',
      content: message,
      isImage: isImage,
      imageFile: imageFile
    };
    
    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);

    try {
      let response;
      
      if (isImage && imageFile) {
        const formData = new FormData();
        formData.append('file', imageFile);
        
        response = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
      } else {
        response = await fetch('/api/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ message })
        });
      }

      // Check if response is OK before parsing
      if (!response.ok) {
        // Try to get error message from response
        let errorData;
        try {
          errorData = await response.json();
        } catch (e) {
          errorData = { message: `Server error: ${response.status} ${response.statusText}` };
        }
        
        throw new Error(errorData.message || `Server error: ${response.status}`);
      }

      const data = await response.json();
      
      // Debug logging
      console.log('API Response:', data);
      console.log('Has Report:', data.has_report);
      
      // Check if backend returned an error status
      if (data.status === 'error') {
        throw new Error(data.message || 'An error occurred on the server');
      }
      
      const botMessage = {
        id: Date.now() + 1,
        type: 'bot',
        content: data.output || data.message || 'No response received',
        agent: data.agent,
        status: data.status,
        hasReport: data.has_report || false
      };
      
      console.log('Bot Message:', botMessage);
      
      setMessages(prev => [...prev, botMessage]);
      
    } catch (error) {
      console.error('Error:', error);
      const errorMessage = {
        id: Date.now() + 1,
        type: 'bot',
        content: error.message || 'Sorry, an error occurred. Please try again.',
        agent: 'Error',
        status: 'error'
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="App">
      {/* Header */}
      <header className="main-header">
        <div className="header-left">
          <div className="logo-icon">🛡️</div>
          <div>
            <h1 className="app-title">Patch Path</h1>
            <p className="app-subtitle">Find the Path to your CVE Patch</p>
          </div>
        </div>
        <div className="header-right">
          <div className="status-indicator">
            <span className="status-dot"></span>
            <span className="status-text">Active</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="main-content">
        <ChatInterface 
          messages={messages}
          onSendMessage={handleSendMessage}
          isLoading={isLoading}
        />
      </div>
    </div>
  );
}

export default App;

