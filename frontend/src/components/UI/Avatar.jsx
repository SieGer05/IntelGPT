import { User, ShieldCheck } from 'lucide-react';

const Avatar = ({ isAi }) => {
   return (
      <div className={`w-8 h-8 rounded flex items-center justify-center shrink-0 ${
         isAi ? 'bg-green-600' : 'bg-blue-600'
      }`}>
         {isAi ? <ShieldCheck size={20} color="white" /> : <User size={20} color="white" />}
      </div>
   );
};

export default Avatar;