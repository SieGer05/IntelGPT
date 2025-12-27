import { Plus, MessageSquare, PanelLeftClose } from 'lucide-react';
import logo from '../../assets/logo.png'; 

const Sidebar = ({ onReset, isOpen, toggleSidebar }) => {
   if (!isOpen) return null;

   return (
      <aside className="hidden md:flex flex-col w-65 h-screen bg-[#181919] p-3 transition-all duration-300">
         <div className="flex items-center justify-between mb-6 px-1">
         <div className="flex items-center gap-2 font-bold text-white text-lg">
            <img src={logo} alt="Logo" className="w-6 h-6" />
         </div>

         <button 
            onClick={toggleSidebar}
            className="p-2 text-gray-400 hover:text-white hover:bg-[#303131] rounded-md transition-colors cursor-e-resize"
            title="Fermer la barre latérale"
         >
            <PanelLeftClose size={18} />
         </button>
         </div>

         <button 
            onClick={onReset}
            className="flex items-center gap-2 w-full px-3 py-3 mb-4 text-sm text-white rounded-4xl hover:bg-[#303131]  transition-colors cursor-pointer"
         >
            <Plus size={16} />
            Nouveau Chat
         </button>

         <div className="flex-1 overflow-y-auto px-1">
            <div className="text-xs text-gray-500 font-bold mb-2 uppercase px-2">Historique</div>
            <div className="flex items-center gap-3 px-3 py-3 text-sm text-gray-300 hover:bg-[#303131] rounded cursor-pointer transition-colors">
               <MessageSquare size={16} /> Session active
            </div>
         </div>
      </aside>
   );
};

export default Sidebar;