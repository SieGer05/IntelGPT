import { useState } from "react";
import { Send } from "lucide-react";

const ChatInput = ({ onSend, disabled, centered }) => {
  const [text, setText] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!disabled && text.trim()) {
      onSend(text);
      setText("");
    }
  };

  const containerClasses = centered
    ? "w-full"
    : "w-full p-4 bg-[#202021] shrink-0"; 

  const inputContainerClasses = `
    relative flex items-center w-full
    bg-[#303131]
    rounded-full
    px-3 py-2
    shadow-sm
  `;

  return (
    <div className={containerClasses}>
      <div className="max-w-3xl mx-auto">
        <form onSubmit={handleSubmit} className={inputContainerClasses}>
          <input
            className="
              w-full
              bg-transparent
              text-white
              placeholder-gray-400
              focus:outline-none
              focus:ring-0
              border-0
              px-2
              text-sm md:text-base
            "
            placeholder={centered ? "Ask anything..." : "Message Secure RAG..."}
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={disabled}
            autoFocus
          />

          <button
            type="submit"
            disabled={disabled || !text.trim()}
            className={`
              p-2 rounded-full transition-all duration-200
              ${text.trim() ? 'bg-white text-black' : 'bg-transparent text-gray-500 cursor-not-allowed'}
            `}
          >
            <Send size={18} />
          </button>
        </form>
        
        <div className="text-center mt-3">
          <p className="text-xs text-gray-500 font-medium">
            Secure RAG Project &copy; 2025 &middot; Designed for Cyber Threat Intelligence & MITRE ATT&CK Analysis.
          </p>
        </div>
      </div>
    </div>
  );
};

export default ChatInput;