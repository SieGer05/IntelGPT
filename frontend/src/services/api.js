import axios from 'axios';

const API_URL = 'http://127.0.0.1:8000';

export const chatService = {
   sendMessage: async (query, history = []) => {
      try {
         // 2. OPTIMISATION : Fenêtre Glissante
         // On garde seulement les 6 derniers messages pour ne pas surcharger l'API
         const recentHistory = history.slice(-6);

         // 3. NETTOYAGE
         const cleanHistory = recentHistory.map(msg => ({
            role: msg.role,
            content: msg.content
         }));

         // 4. ENVOI
         // On envoie 'query' ET 'history' au backend
         const response = await axios.post(`${API_URL}/chat`, { 
            query: query,
            history: cleanHistory 
         });
         
         return response.data;
      } catch (error) {
         console.error("API Error:", error);
         throw error;
      }
   }
};