import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Loader2 } from 'lucide-react';

const Logs = () => {
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await fetch(`http://${window.location.hostname}:8000/api/logs`);
      if (!response.ok) {
        throw new Error('Failed to fetch logs');
      }
      const data = await response.json();
      setLogs(data.logs);
      setMetrics(data.metrics);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    // Auto-refresh every 5 seconds
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex h-screen bg-[#202021] text-white font-sans overflow-hidden">
      {/* Sidebar Overlay */}
      <div className="flex-1 flex flex-col relative h-full overflow-hidden">
         <div className="h-full overflow-y-auto p-6">
            <div className="max-w-7xl mx-auto">
              <header className="mb-8 flex justify-between items-center">
                <div>
                  <h1 className="text-3xl font-bold ">
                    System Logs & Security
                  </h1>
                  <p className="text-gray-400 mt-2">Real-time monitoring of API requests and security events</p>
                </div>
                <div className="flex gap-4">
                  <Link to="/" className="px-4 py-2 bg-[#2f2f2f] hover:bg-[#424242] rounded-lg transition-colors font-medium text-sm text-gray-300">
                     Back to Chat
                  </Link>
                  <button 
                    onClick={fetchLogs}
                    disabled={loading}
                    className={`
                      px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors font-medium text-sm
                      flex items-center gap-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed
                    `}
                  >
                    {loading && <Loader2 className="animate-spin" size={16} />}
                    Refresh Now
                  </button>
                </div>
              </header>

              {error && (
                <div className="bg-red-500/10 border border-red-500/50 p-4 rounded-xl text-red-200 mb-6">
                  Error: {error}
                </div>
              )}

              {/* METRICS CARDS */}
              {metrics && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                  <div className="bg-[#2f2f2f] p-6 rounded-xl border border-transparent shadow-lg relative overflow-hidden group hover:border-gray-600 transition-all">
                    <div className="absolute top-0 right-0 w-24 h-24 bg-blue-500/10 rounded-full blur-2xl -mr-8 -mt-8"></div>
                    <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Total Visible Logs</h3>
                    <p className="text-4xl font-bold text-white">{metrics.total_visible}</p>
                  </div>

                  <div className="bg-[#2f2f2f] p-6 rounded-xl border border-transparent shadow-lg relative overflow-hidden group hover:border-gray-600 transition-all">
                    <div className="absolute top-0 right-0 w-24 h-24 bg-green-500/10 rounded-full blur-2xl -mr-8 -mt-8"></div>
                    <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">HTTP Requests</h3>
                    <p className="text-4xl font-bold text-green-400">{metrics.http_requests}</p>
                  </div>

                  <div className="bg-[#2f2f2f] p-6 rounded-xl border border-transparent shadow-lg relative overflow-hidden group hover:border-gray-600 transition-all">
                    <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/10 rounded-full blur-2xl -mr-8 -mt-8"></div>
                    <h3 className="text-gray-400 text-sm font-medium uppercase tracking-wider mb-2">Security Events</h3>
                    <p className="text-4xl font-bold text-red-500">{metrics.security_events}</p>
                  </div>
                </div>
              )}

              {/* LOGS TABLE */}
              <div className="bg-[#2f2f2f] rounded-xl border border-transparent shadow-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-[#202021] border-b border-gray-700">
                        <th className="p-4 py-5 text-gray-400 font-semibold text-xs uppercase tracking-wider">Timestamp</th>
                        <th className="p-4 py-5 text-gray-400 font-semibold text-xs uppercase tracking-wider">Level</th>
                        <th className="p-4 py-5 text-gray-400 font-semibold text-xs uppercase tracking-wider">Event Type</th>
                        <th className="p-4 py-5 text-gray-400 font-semibold text-xs uppercase tracking-wider">Details</th>
                        <th className="p-4 py-5 text-gray-400 font-semibold text-xs uppercase tracking-wider text-right">Metric</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700/50">
                      {logs.map((log, index) => {
                        const isCritical = log.is_critical || log.level === 'WARNING';
                        const isSecurity = log.event === 'security_violation';
                        
                        return (
                          <tr 
                            key={index} 
                            className={`
                              hover:bg-white/5 transition-colors text-sm
                              ${isCritical ? 'bg-red-500/10 border-l-4 border-l-red-500' : ''}
                            `}
                          >
                            <td className="p-4 text-gray-400 whitespace-nowrap font-mono text-xs">
                              {log.timestamp.split(' ')[1]} 
                            </td>
                            
                            <td className="p-4">
                              <span className={`
                                px-2 py-1 rounded text-xs font-bold
                                ${log.level === 'INFO' ? 'bg-blue-500/20 text-blue-300' : ''}
                                ${isCritical ? 'bg-red-500/20 text-red-300 animate-pulse' : ''}
                              `}>
                                {isCritical ? 'CRITICAL' : log.level}
                              </span>
                            </td>

                            <td className="p-4">
                              <span className="text-gray-300 font-medium">
                                {log.event || 'System'}
                              </span>
                            </td>

                            <td className="p-4 text-gray-300">
                              <div className="flex flex-col gap-1">
                                <span className="text-gray-200">{log.message}</span>
                                {log.path && (
                                  <span className="text-xs text-gray-500 font-mono">
                                    {log.method} {log.path} ({log.status_code})
                                  </span>
                                )}
                                {/* Display Prompt if available */}
                                {log.prompt && log.prompt !== "N/A" && (
                                   <div className="mt-1 p-2 bg-black/30 rounded text-xs border border-gray-700">
                                      <span className="text-gray-500 uppercase text-[10px] font-bold block mb-1">User Prompt:</span>
                                      <span className="text-gray-300 font-mono">{log.prompt}</span>
                                   </div>
                                )}
                                {log.client_ip && (
                                  <span className="text-xs text-gray-500">IP: {log.client_ip}</span>
                                )}
                                {log.violation_type && (
                                  <span className="text-xs text-red-400 font-mono">
                                    Violation: {log.violation_type} | Input: "{log.input_sample}"
                                  </span>
                                )}
                              </div>
                            </td>

                            <td className="p-4 text-right font-mono text-gray-500 text-xs">
                              {log.duration_seconds ? `${log.duration_seconds}s` : '-'}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
         </div>
      </div>
    </div>
  );
};

export default Logs;
