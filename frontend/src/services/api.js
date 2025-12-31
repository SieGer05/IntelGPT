import axios from 'axios';

// Detect connection host (localhost or network IP)
const API_URL = `http://${window.location.hostname}:8000`;

export const chatService = {
   sendMessage: async (query, history = [], filters = null) => {
      try {
         // 2. OPTIMISATION : Fenêtre Glissante
         // On garde seulement les 6 derniers messages pour ne pas surcharger l'API
         const recentHistory = history.slice(-6);

         // 3. NETTOYAGE
         const cleanHistory = recentHistory.map(msg => ({
            role: msg.role,
            content: msg.content
         }));

         // 4. Clean filters - remove null/empty values
         let cleanFilters = null;
         if (filters) {
            cleanFilters = {};
            if (filters.tactics?.length > 0) cleanFilters.tactics = filters.tactics;
            if (filters.platforms?.length > 0) cleanFilters.platforms = filters.platforms;
            if (filters.source) cleanFilters.source = filters.source;
            if (filters.chunk_type) cleanFilters.chunk_type = filters.chunk_type;
            if (filters.is_subtechnique !== null && filters.is_subtechnique !== undefined) {
               cleanFilters.is_subtechnique = filters.is_subtechnique;
            }
            // If no filters are active, set to null
            if (Object.keys(cleanFilters).length === 0) cleanFilters = null;
         }

         // 5. ENVOI
         // On envoie 'query', 'history', et 'filters' au backend
         const response = await axios.post(`${API_URL}/chat`, {
            query: query,
            history: cleanHistory,
            filters: cleanFilters
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

export const filterService = {
   getFilterOptions: async () => {
      try {
         const response = await axios.get(`${API_URL}/api/filters`);
         return response.data;
      } catch (error) {
         console.error("Failed to fetch filter options:", error);
         // Return empty defaults on error
         return {
            tactics: [],
            platforms: [],
            sources: [],
            chunk_types: []
         };
      }
   }
};

export const searchService = {
   search: async (query, nResults = 5, searchMode = 'hybrid', filters = null) => {
      try {
         // Clean filters
         let cleanFilters = null;
         if (filters) {
            cleanFilters = {};
            if (filters.tactics?.length > 0) cleanFilters.tactics = filters.tactics;
            if (filters.platforms?.length > 0) cleanFilters.platforms = filters.platforms;
            if (filters.source) cleanFilters.source = filters.source;
            if (filters.chunk_type) cleanFilters.chunk_type = filters.chunk_type;
            if (Object.keys(cleanFilters).length === 0) cleanFilters = null;
         }

         const response = await axios.post(`${API_URL}/search`, {
            query: query,
            n_results: nResults,
            search_mode: searchMode,
            filters: cleanFilters
         });
         return response.data;
      } catch (error) {
         console.error("Search API Error:", error);
         throw new Error("Search failed.");
      }
   }
};