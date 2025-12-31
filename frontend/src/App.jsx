import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Chat from './pages/Chat';
import Logs from './pages/Logs';
import { ChatProvider } from './context/ChatContext';

function App() {
  return (
    <ChatProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Chat />} />
          <Route path="/logs" element={<Logs />} />
        </Routes>
      </BrowserRouter>
    </ChatProvider>
  );
}

export default App;