import { useState } from "react";
import { Copy, Check } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

const MessageItem = ({ message }) => {
   const isAi = message.role === "assistant";
   const [isCopied, setIsCopied] = useState(false);

   const handleCopy = async () => {
      if (!message.content) return;
      try {
         await navigator.clipboard.writeText(message.content);
         setIsCopied(true);
         setTimeout(() => setIsCopied(false), 2000);
      } catch (err) {
         console.error("Failed to copy text:", err);
      }
   };

   return (
      <div className="w-full py-4 px-4 group">
         <div
         className={`max-w-3xl mx-auto flex ${
            isAi ? "justify-start" : "justify-end"
         }`}
         >
         <div
            className={`
               relative max-w-[85%] md:max-w-lg flex flex-col
               ${
               !isAi
                  ? "bg-[#303131] p-4 rounded-2xl rounded-tr-sm text-white"
                  : "bg-transparent text-white items-start"
               }
            `}
         >
            <div className="prose prose-invert max-w-none leading-relaxed text-left">
               {isAi ? (
               <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                     p: ({ node, ...props }) => (
                        <p className="mb-2 last:mb-0" {...props} />
                     ),
                     strong: ({ node, ...props }) => (
                        <strong className="font-semibold text-white" {...props} />
                     ),
                     ul: ({ node, ...props }) => (
                        <ul className="list-disc pl-5 mb-2" {...props} />
                     ),
                  }}
               >
                  {message.content}
               </ReactMarkdown>
               ) : (
                  <p className="whitespace-pre-wrap m-0">{message.content}</p>
               )}
            </div>

            {isAi && (
               <div className="mt-2 flex items-center gap-3 select-none">
               <button
                  onClick={handleCopy}
                  className="flex items-center gap-1 text-xs text-gray-500 hover:text-white transition-colors rounded cursor-pointer"
                  title="Copier le message"
               >
                  {isCopied ? (
                     <>
                     <Check size={14} className="text-green-500" />
                     <span className="text-green-500">Copié !</span>
                     </>
                  ) : (
                     <>
                     <Copy size={14} />
                     <span>Copier</span>
                     </>
                  )}
               </button>
               </div>
            )}

            {isAi && message.sources?.length > 0 && (
               <div className="mt-3 p-3 bg-[#303131] rounded-lg text-xs w-full self-start">
               <span className="font-bold text-gray-400 block mb-1 uppercase tracking-wider">
                  Sources :
               </span>
               <ul className="list-disc pl-4 space-y-1 text-gray-400">
                  {message.sources.map((src, idx) => (
                     <li key={idx}>{src}</li>
                  ))}
               </ul>
               </div>
            )}
         </div>
         </div>
      </div>
   );
};

export default MessageItem;