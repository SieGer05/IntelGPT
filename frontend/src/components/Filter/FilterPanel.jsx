import { useState, useEffect } from 'react';
import { Filter, X, ChevronDown, ChevronUp, Shield, Cpu, Crosshair, FileType } from 'lucide-react';
import { filterService } from '../../services/api';

const FilterPanel = ({ filters, onFiltersChange, isOpen, onToggle }) => {
   const [filterOptions, setFilterOptions] = useState({
      tactics: [],
      platforms: [],
      sources: [],
      chunk_types: []
   });
   const [loading, setLoading] = useState(true);
   const [expandedSections, setExpandedSections] = useState({
      tactics: true,
      platforms: true,
      source: false,
      chunk_type: false
   });

   // Fetch available filter options on mount
   useEffect(() => {
      const fetchFilters = async () => {
         try {
            const options = await filterService.getFilterOptions();
            setFilterOptions(options);
         } catch (error) {
            console.error('Failed to load filter options:', error);
         } finally {
            setLoading(false);
         }
      };
      fetchFilters();
   }, []);

   const toggleSection = (section) => {
      setExpandedSections(prev => ({
         ...prev,
         [section]: !prev[section]
      }));
   };

   const handleTacticToggle = (tactic) => {
      const currentTactics = filters.tactics || [];
      const newTactics = currentTactics.includes(tactic)
         ? currentTactics.filter(t => t !== tactic)
         : [...currentTactics, tactic];
      
      onFiltersChange({
         ...filters,
         tactics: newTactics.length > 0 ? newTactics : null
      });
   };

   const handlePlatformToggle = (platform) => {
      const currentPlatforms = filters.platforms || [];
      const newPlatforms = currentPlatforms.includes(platform)
         ? currentPlatforms.filter(p => p !== platform)
         : [...currentPlatforms, platform];
      
      onFiltersChange({
         ...filters,
         platforms: newPlatforms.length > 0 ? newPlatforms : null
      });
   };

   const handleSourceChange = (source) => {
      onFiltersChange({
         ...filters,
         source: filters.source === source ? null : source
      });
   };

   const handleChunkTypeChange = (chunkType) => {
      onFiltersChange({
         ...filters,
         chunk_type: filters.chunk_type === chunkType ? null : chunkType
      });
   };

   const clearAllFilters = () => {
      onFiltersChange({
         tactics: null,
         platforms: null,
         source: null,
         chunk_type: null,
         is_subtechnique: null
      });
   };

   const getActiveFilterCount = () => {
      let count = 0;
      if (filters.tactics?.length) count += filters.tactics.length;
      if (filters.platforms?.length) count += filters.platforms.length;
      if (filters.source) count += 1;
      if (filters.chunk_type) count += 1;
      if (filters.is_subtechnique !== null && filters.is_subtechnique !== undefined) count += 1;
      return count;
   };

   const activeCount = getActiveFilterCount();

   // Tactic display names with colors
   const tacticColors = {
      'reconnaissance': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      'resource-development': 'bg-purple-500/20 text-purple-400 border-purple-500/30',
      'initial-access': 'bg-green-500/20 text-green-400 border-green-500/30',
      'execution': 'bg-red-500/20 text-red-400 border-red-500/30',
      'persistence': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      'privilege-escalation': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'defense-evasion': 'bg-pink-500/20 text-pink-400 border-pink-500/30',
      'credential-access': 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
      'discovery': 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
      'lateral-movement': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
      'collection': 'bg-teal-500/20 text-teal-400 border-teal-500/30',
      'command-and-control': 'bg-violet-500/20 text-violet-400 border-violet-500/30',
      'exfiltration': 'bg-rose-500/20 text-rose-400 border-rose-500/30',
      'impact': 'bg-amber-500/20 text-amber-400 border-amber-500/30',
      'exploitation': 'bg-red-600/20 text-red-500 border-red-600/30'
   };

   const getTacticColor = (tactic) => {
      return tacticColors[tactic] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';
   };

   const formatTacticName = (tactic) => {
      return tactic
         .split('-')
         .map(word => word.charAt(0).toUpperCase() + word.slice(1))
         .join(' ');
   };

   if (!isOpen) {
      return (
         <button
            onClick={onToggle}
            className="flex items-center gap-2 px-3 py-2 bg-[#303131] hover:bg-[#424242] rounded-lg transition-colors text-sm text-gray-300"
         >
            <Filter size={16} />
            <span>Filters</span>
            {activeCount > 0 && (
               <span className="bg-blue-500 text-white text-xs px-2 py-0.5 rounded-full">
                  {activeCount}
               </span>
            )}
         </button>
      );
   }

   return (
      <div className="bg-[#181919] border border-[#303131] rounded-xl p-4 w-72 max-h-[70vh] overflow-y-auto">
         {/* Header */}
         <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#303131]">
            <div className="flex items-center gap-2">
               <Filter size={18} className="text-blue-400" />
               <h3 className="text-white font-medium">Dynamic Filters</h3>
               {activeCount > 0 && (
                  <span className="bg-blue-500 text-white text-xs px-2 py-0.5 rounded-full">
                     {activeCount}
                  </span>
               )}
            </div>
            <div className="flex items-center gap-2">
               {activeCount > 0 && (
                  <button
                     onClick={clearAllFilters}
                     className="text-xs text-red-400 hover:text-red-300 transition-colors"
                  >
                     Clear all
                  </button>
               )}
               <button
                  onClick={onToggle}
                  className="p-1 text-gray-400 hover:text-white transition-colors"
               >
                  <X size={16} />
               </button>
            </div>
         </div>

         {loading ? (
            <div className="text-gray-400 text-sm text-center py-4">Loading filters...</div>
         ) : (
            <div className="space-y-4">
               {/* Source Section */}
               <div className="border-b border-[#303131] pb-3">
                  <button
                     onClick={() => toggleSection('source')}
                     className="flex items-center justify-between w-full text-left mb-2"
                  >
                     <div className="flex items-center gap-2 text-gray-300 text-sm font-medium">
                        <Shield size={14} />
                        <span>Data Source</span>
                     </div>
                     {expandedSections.source ? <ChevronUp size={14} className="text-gray-400" /> : <ChevronDown size={14} className="text-gray-400" />}
                  </button>
                  {expandedSections.source && (
                     <div className="space-y-1 mt-2">
                        {filterOptions.sources.map(source => (
                           <button
                              key={source}
                              onClick={() => handleSourceChange(source)}
                              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                                 filters.source === source
                                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                    : 'text-gray-400 hover:bg-[#303131] border border-transparent'
                              }`}
                           >
                              {source}
                           </button>
                        ))}
                     </div>
                  )}
               </div>

               {/* Tactics Section */}
               <div className="border-b border-[#303131] pb-3">
                  <button
                     onClick={() => toggleSection('tactics')}
                     className="flex items-center justify-between w-full text-left mb-2"
                  >
                     <div className="flex items-center gap-2 text-gray-300 text-sm font-medium">
                        <Crosshair size={14} />
                        <span>Tactics</span>
                        {(filters.tactics?.length > 0) && (
                           <span className="text-xs text-blue-400">({filters.tactics.length})</span>
                        )}
                     </div>
                     {expandedSections.tactics ? <ChevronUp size={14} className="text-gray-400" /> : <ChevronDown size={14} className="text-gray-400" />}
                  </button>
                  {expandedSections.tactics && (
                     <div className="flex flex-wrap gap-1.5 mt-2">
                        {filterOptions.tactics.map(tactic => (
                           <button
                              key={tactic}
                              onClick={() => handleTacticToggle(tactic)}
                              className={`px-2 py-1 rounded text-xs transition-colors border ${
                                 (filters.tactics || []).includes(tactic)
                                    ? getTacticColor(tactic)
                                    : 'text-gray-400 hover:bg-[#303131] border-transparent hover:border-gray-600'
                              }`}
                           >
                              {formatTacticName(tactic)}
                           </button>
                        ))}
                     </div>
                  )}
               </div>

               {/* Platforms Section */}
               <div className="border-b border-[#303131] pb-3">
                  <button
                     onClick={() => toggleSection('platforms')}
                     className="flex items-center justify-between w-full text-left mb-2"
                  >
                     <div className="flex items-center gap-2 text-gray-300 text-sm font-medium">
                        <Cpu size={14} />
                        <span>Platforms</span>
                        {(filters.platforms?.length > 0) && (
                           <span className="text-xs text-blue-400">({filters.platforms.length})</span>
                        )}
                     </div>
                     {expandedSections.platforms ? <ChevronUp size={14} className="text-gray-400" /> : <ChevronDown size={14} className="text-gray-400" />}
                  </button>
                  {expandedSections.platforms && (
                     <div className="flex flex-wrap gap-1.5 mt-2">
                        {filterOptions.platforms.map(platform => (
                           <button
                              key={platform}
                              onClick={() => handlePlatformToggle(platform)}
                              className={`px-2 py-1 rounded text-xs transition-colors border ${
                                 (filters.platforms || []).includes(platform)
                                    ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                                    : 'text-gray-400 hover:bg-[#303131] border-transparent hover:border-gray-600'
                              }`}
                           >
                              {platform}
                           </button>
                        ))}
                     </div>
                  )}
               </div>

               {/* Content Type Section */}
               <div>
                  <button
                     onClick={() => toggleSection('chunk_type')}
                     className="flex items-center justify-between w-full text-left mb-2"
                  >
                     <div className="flex items-center gap-2 text-gray-300 text-sm font-medium">
                        <FileType size={14} />
                        <span>Content Type</span>
                     </div>
                     {expandedSections.chunk_type ? <ChevronUp size={14} className="text-gray-400" /> : <ChevronDown size={14} className="text-gray-400" />}
                  </button>
                  {expandedSections.chunk_type && (
                     <div className="space-y-1 mt-2">
                        {filterOptions.chunk_types.map(chunkType => (
                           <button
                              key={chunkType}
                              onClick={() => handleChunkTypeChange(chunkType)}
                              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors capitalize ${
                                 filters.chunk_type === chunkType
                                    ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                                    : 'text-gray-400 hover:bg-[#303131] border border-transparent'
                              }`}
                           >
                              {chunkType}
                           </button>
                        ))}
                     </div>
                  )}
               </div>
            </div>
         )}

         {/* Active Filters Summary */}
         {activeCount > 0 && (
            <div className="mt-4 pt-3 border-t border-[#303131]">
               <p className="text-xs text-gray-500 mb-2">Active filters will refine your search results</p>
               <div className="flex flex-wrap gap-1">
                  {filters.source && (
                     <span className="px-2 py-1 bg-blue-500/10 text-blue-400 text-xs rounded flex items-center gap-1">
                        {filters.source}
                        <X size={10} className="cursor-pointer" onClick={() => handleSourceChange(filters.source)} />
                     </span>
                  )}
                  {(filters.tactics || []).map(t => (
                     <span key={t} className={`px-2 py-1 text-xs rounded flex items-center gap-1 ${getTacticColor(t)}`}>
                        {formatTacticName(t)}
                        <X size={10} className="cursor-pointer" onClick={() => handleTacticToggle(t)} />
                     </span>
                  ))}
                  {(filters.platforms || []).map(p => (
                     <span key={p} className="px-2 py-1 bg-emerald-500/10 text-emerald-400 text-xs rounded flex items-center gap-1">
                        {p}
                        <X size={10} className="cursor-pointer" onClick={() => handlePlatformToggle(p)} />
                     </span>
                  ))}
                  {filters.chunk_type && (
                     <span className="px-2 py-1 bg-purple-500/10 text-purple-400 text-xs rounded flex items-center gap-1 capitalize">
                        {filters.chunk_type}
                        <X size={10} className="cursor-pointer" onClick={() => handleChunkTypeChange(filters.chunk_type)} />
                     </span>
                  )}
               </div>
            </div>
         )}
      </div>
   );
};

export default FilterPanel;
