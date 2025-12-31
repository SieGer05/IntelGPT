import { useState, useRef, useEffect } from 'react';
import Sidebar from '../components/Sidebar/Sidebar';
import MessageItem from '../components/Chat/MessageItem';
import ChatInput from '../components/Chat/ChatInput';
import LoadingSpinner from '../components/UI/LoadingSpinner';
import FilterPanel from '../components/Filter/FilterPanel';
import { chatService } from '../services/api';
import { useChat } from '../context/ChatContext';

function Chat() {
  const { messages, setMessages } = useChat();
  const [loading, setLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [filters, setFilters] = useState({
    tactics: null,
    platforms: null,
    source: null,
    chunk_type: null,
    is_subtechnique: null
  });

  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (text) => {
    const currentHistory = messages;

    setMessages(prev => [...prev, { role: 'user', content: text }]);
    setLoading(true);

    try {
      const data = await chatService.sendMessage(text, currentHistory, filters);

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.answer,
        sources: data.sources,
        appliedFilters: data.applied_filters
      }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: error.message || "Erreur de connexion au serveur.",
        isError: true
      }]);
    } finally {
      setLoading(false);
    }
  };

  const getActiveFilterCount = () => {
    let count = 0;
    if (filters.tactics?.length) count += filters.tactics.length;
    if (filters.platforms?.length) count += filters.platforms.length;
    if (filters.source) count += 1;
    if (filters.chunk_type) count += 1;
    return count;
  };

  return (
    <div className="flex h-screen bg-[#202021] text-white font-sans overflow-hidden">
      <Sidebar
        onReset={() => {
          setMessages([]);
          setFilters({
            tactics: null,
            platforms: null,
            source: null,
            chunk_type: null,
            is_subtechnique: null
          });
        }}
        isOpen={isSidebarOpen}
        toggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)}
      />

      <div className="flex-1 flex flex-col relative h-full">
        {/* Filter Toggle Button - Fixed position */}
        <div className="absolute top-4 right-4 z-10">
          <FilterPanel
            filters={filters}
            onFiltersChange={setFilters}
            isOpen={isFilterOpen}
            onToggle={() => setIsFilterOpen(!isFilterOpen)}
          />
        </div>

        {messages.length === 0 ? (
          <div className="flex-1 flex flex-col justify-center items-center p-4">
            <div className="mb-8 flex flex-col items-center">
              <h1 className="text-3xl font-semibold text-gray-200">What's on the agenda today?</h1>
              {getActiveFilterCount() > 0 && (
                <p className="text-sm text-blue-400 mt-2">
                  {getActiveFilterCount()} filter{getActiveFilterCount() > 1 ? 's' : ''} active
                </p>
              )}
            </div>

            <div className="w-full max-w-2xl">
              <ChatInput onSend={handleSend} disabled={loading} centered={true} />
            </div>

            <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-3 max-w-2xl w-full">
              <button onClick={() => handleSend("What is Phishing?")} className="p-4 bg-[#2f2f2f] rounded-xl hover:bg-[#424242] transition-colors text-sm text-gray-300 text-left cursor-pointer border border-transparent hover:border-gray-600">
                <span className="font-medium block mb-1">What is Phishing?</span>
                <span className="text-gray-500 text-xs">Learn about email attacks</span>
              </button>
              <button onClick={() => handleSend("List MITRE techniques for Linux")} className="p-4 bg-[#2f2f2f] rounded-xl hover:bg-[#424242] transition-colors text-sm text-gray-300 text-left cursor-pointer border border-transparent hover:border-gray-600">
                <span className="font-medium block mb-1">Linux Techniques</span>
                <span className="text-gray-500 text-xs">Explore MITRE ATT&CK</span>
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="flex-1 overflow-y-auto scroll-smooth pt-16">
              {messages.map((msg, index) => (
                <MessageItem key={index} message={msg} />
              ))}

              {loading && (
                <div className="w-full bg-[#202021] p-6">
                  <div className="max-w-3xl mx-auto">
                    <LoadingSpinner />
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            <ChatInput onSend={handleSend} disabled={loading} centered={false} />
          </>
        )}
      </div>
    </div>
  );
}

export default Chat;
