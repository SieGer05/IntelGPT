import axios from 'axios';

// Detect connection host (localhost or network IP)
const API_URL = `http://${window.location.hostname}:8000`;

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
         // Extract error detail from API response if available
         if (error.response && error.response.data && error.response.data.detail) {
            throw new Error(error.response.data.detail);
         }
         throw new Error("Erreur de connexion au serveur.");
      }
   }
};