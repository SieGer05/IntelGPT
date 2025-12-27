import axios from 'axios';

const API_URL = 'http://127.0.0.1:8000';

export const chatService = {
   sendMessage: async (query) => {
      try {
         const response = await axios.post(`${API_URL}/chat`, { query });
         return response.data;
      } catch (error) {
         console.error("API Error:", error);
         throw error;
      }
   }
};