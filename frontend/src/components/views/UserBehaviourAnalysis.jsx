import React, { useState } from 'react';
import { Brain, Eye, TrendingUp, Clock } from 'lucide-react';
import { Card } from '../core/Card';
import { LiveLogTerminal } from '../core/LiveLogTerminal';
import { mockAPI } from '../../api/mockAPI';

export function UserBehaviourAnalysis({ fileUrl, activeDevices = [] }) {
  const [loading, setLoading] = useState(false);
  const [behaviourData, setBehaviourData] = useState(null);
  const [logs, setLogs] = useState([]);

  const addLog = (line) => {
    const ts = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { ts, line }]);
  };

  const runBehaviourAnalysis = async () => {
    setLoading(true);
    setLogs([]);
    addLog('Starting user behaviour analysis...');
    
    try {
      const { jobId } = await mockAPI.startJob('behaviour-analysis', fileUrl);
      addLog(`Behaviour analysis job created: ${jobId}`);
      
      await new Promise(r => setTimeout(r, 1000));
      addLog('Analyzing device interaction patterns...');
      
      await new Promise(r => setTimeout(r, 1500));
      addLog('Correlating temporal activity sequences...');
      
      await new Promise(r => setTimeout(r, 1000));
      addLog('Identifying user routine patterns...');
      
      await new Promise(r => setTimeout(r, 800));
      addLog('Processing behavioral fingerprints...');
      
      await new Promise(r => setTimeout(r, 1200));
      addLog('Generating user profile insights...');

      // Generate mock behaviour data based on active devices
      const mockBehaviourData = generateBehaviourAnalysis(activeDevices);
      setBehaviourData(mockBehaviourData);
      
      addLog(`Behaviour analysis complete! Identified ${mockBehaviourData.patterns.length} behavior patterns.`);
      
    } catch (err) {
      addLog(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const generateBehaviourAnalysis = (devices) => {
    const activeDeviceCount = devices.filter(d => d.isActive).length;
    const totalPackets = devices.reduce((sum, d) => sum + (d.packetCount || 0), 0);
    
    // Generate behavior patterns based on device types and actions
    const patterns = [];
    const insights = [];
    const riskFactors = [];
    
    devices.forEach(device => {
      if (!device.isActive) return;
      
      // Generate patterns based on device type
      switch (device.fingerprint) {
        case 'iPhone 12':
        case 'Android Phone':
          patterns.push({
            type: 'Mobile Usage',
            description: 'Heavy mobile device activity detected',
            confidence: 0.89,
            timeWindow: 'Last 15 minutes',
            indicators: ['Background app refresh', 'Social media sync', 'Location tracking'],
            riskLevel: 'Medium'
          });
          insights.push('User appears to be actively using mobile device with multiple apps');
          break;
          
        case 'Smart TV':
          patterns.push({
            type: 'Media Consumption',
            description: 'Streaming media content behavior',
            confidence: 0.94,
            timeWindow: 'Ongoing',
            indicators: ['Video streaming', 'Remote control activity', 'Bandwidth usage'],
            riskLevel: 'Low'
          });
          insights.push('User engaged in media streaming or entertainment activities');
          break;
          
        case 'Linux Device':
        case 'Laptop':
          patterns.push({
            type: 'Work Activity',
            description: 'Professional or technical work behavior',
            confidence: 0.76,
            timeWindow: 'Last 30 minutes',
            indicators: ['SSH connections', 'File transfers', 'Network scanning'],
            riskLevel: 'High'
          });
          insights.push('Technical user with potential system administration activities');
          riskFactors.push('Elevated network scanning activity detected');
          break;
      }
    });
    
    // Add general patterns based on overall activity
    if (activeDeviceCount > 2) {
      patterns.push({
        type: 'Multi-Device Usage',
        description: 'Simultaneous usage of multiple devices',
        confidence: 0.82,
        timeWindow: 'Current session',
        indicators: ['Device synchronization', 'Cross-platform activity', 'Resource sharing'],
        riskLevel: 'Medium'
      });
      insights.push('User demonstrates multi-device workflow patterns');
    }
    
    if (totalPackets > 500) {
      patterns.push({
        type: 'High Activity User',
        description: 'Above-average network activity levels',
        confidence: 0.91,
        timeWindow: 'Session duration',
        indicators: ['High packet volume', 'Frequent connections', 'Data-intensive apps'],
        riskLevel: 'Medium'
      });
      insights.push('User exhibits high network utilization patterns');
    }
    
    // Generate time-based patterns
    const currentHour = new Date().getHours();
    if (currentHour >= 9 && currentHour <= 17) {
      patterns.push({
        type: 'Business Hours Activity',
        description: 'Activity during typical work hours',
        confidence: 0.85,
        timeWindow: 'Business hours',
        indicators: ['Work-related traffic', 'Productivity apps', 'Communication tools'],
        riskLevel: 'Low'
      });
    } else if (currentHour >= 18 && currentHour <= 23) {
      patterns.push({
        type: 'Evening Leisure',
        description: 'Recreation and entertainment patterns',
        confidence: 0.78,
        timeWindow: 'Evening hours',
        indicators: ['Entertainment apps', 'Social media', 'Streaming services'],
        riskLevel: 'Low'
      });
    }
    
    return {
      summary: {
        totalDevicesAnalyzed: devices.length,
        activeDevices: activeDeviceCount,
        patternsIdentified: patterns.length,
        overallRiskLevel: calculateOverallRisk(patterns),
        analysisConfidence: 0.84
      },
      patterns,
      insights,
      riskFactors,
      recommendations: generateRecommendations(patterns, riskFactors),
      timelineData: generateTimelineData(devices)
    };
  };

  const calculateOverallRisk = (patterns) => {
    const riskLevels = patterns.map(p => p.riskLevel);
    if (riskLevels.includes('High')) return 'High';
    if (riskLevels.includes('Medium')) return 'Medium';
    return 'Low';
  };

  const generateRecommendations = (patterns, riskFactors) => {
    const recommendations = [];
    
    if (riskFactors.length > 0) {
      recommendations.push('Monitor network scanning activities for potential security threats');
      recommendations.push('Implement network access controls for technical devices');
    }
    
    if (patterns.some(p => p.type === 'Multi-Device Usage')) {
      recommendations.push('Consider device synchronization security policies');
      recommendations.push('Implement unified endpoint management');
    }
    
    if (patterns.some(p => p.type === 'High Activity User')) {
      recommendations.push('Monitor bandwidth usage patterns');
      recommendations.push('Consider data loss prevention measures');
    }
    
    recommendations.push('Regular behavior pattern reviews recommended');
    recommendations.push('Consider user activity baseline establishment');
    
    return recommendations;
  };

  const generateTimelineData = (devices) => {
    return devices.filter(d => d.isActive).map((device, i) => ({
      time: new Date(Date.now() - (i * 60000)).toLocaleTimeString(),
      event: `${device.fingerprint} activity detected`,
      type: device.trafficType,
      intensity: Math.floor(Math.random() * 100) + 1
    }));
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'High': return 'text-red-400 border-red-500/30';
      case 'Medium': return 'text-yellow-400 border-yellow-500/30';
      case 'Low': return 'text-green-400 border-green-500/30';
      default: return 'text-gray-400 border-gray-500/30';
    }
  };

  const getConfidenceColor = (confidence) => {
    if (confidence > 0.8) return 'text-green-400';
    if (confidence > 0.6) return 'text-yellow-400';
    return 'text-red-400';
  };

  return (
    <div className="space-y-4">
      <Card title="User Behaviour Analysis" icon={Brain}>
        <div className="space-y-4">
          <div className="text-xs text-gray-400">
            {activeDevices.length > 0 
              ? `Analyzing user patterns from ${activeDevices.filter(d => d.isActive).length} active devices`
              : 'Run device action identification first for behavior analysis'
            }
          </div>
          
          <button
            onClick={runBehaviourAnalysis}
            disabled={!fileUrl || loading || activeDevices.length === 0}
            className="w-full px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500 text-cyan-400 rounded font-mono text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <Eye className="w-4 h-4" />
            {loading ? 'Analyzing Behaviour...' : 'Analyze User Behaviour'}
          </button>

          {behaviourData && (
            <div className="mt-4 space-y-4">
              {/* Summary Card */}
              <div className="bg-black/30 rounded p-4 border border-cyan-500/20">
                <div className="flex items-center gap-2 text-sm text-cyan-400 mb-3">
                  <TrendingUp className="w-4 h-4" />
                  Analysis Summary
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                  <div>
                    <span className="text-gray-400">Devices:</span>
                    <span className="text-white ml-2">{behaviourData.summary.activeDevices}/{behaviourData.summary.totalDevicesAnalyzed}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Patterns:</span>
                    <span className="text-white ml-2">{behaviourData.summary.patternsIdentified}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Risk Level:</span>
                    <span className={`ml-2 ${getRiskColor(behaviourData.summary.overallRiskLevel).split(' ')[0]}`}>
                      {behaviourData.summary.overallRiskLevel}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-400">Confidence:</span>
                    <span className={`ml-2 ${getConfidenceColor(behaviourData.summary.analysisConfidence)}`}>
                      {(behaviourData.summary.analysisConfidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Behavior Patterns */}
              <div>
                <div className="text-sm text-cyan-400 mb-3">Identified Behavior Patterns</div>
                <div className="space-y-3">
                  {behaviourData.patterns.map((pattern, i) => (
                    <div key={i} className={`bg-black/30 rounded p-3 border ${getRiskColor(pattern.riskLevel).split(' ')[1]}`}>
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <div className="text-sm font-mono text-white">{pattern.type}</div>
                          <div className="text-xs text-gray-400">{pattern.description}</div>
                        </div>
                        <div className="text-right">
                          <div className={`text-xs ${getConfidenceColor(pattern.confidence)}`}>
                            {(pattern.confidence * 100).toFixed(0)}%
                          </div>
                          <div className={`text-xs ${getRiskColor(pattern.riskLevel).split(' ')[0]}`}>
                            {pattern.riskLevel}
                          </div>
                        </div>
                      </div>
                      
                      <div className="text-xs text-gray-500 mb-2">
                        <Clock className="w-3 h-3 inline mr-1" />
                        {pattern.timeWindow}
                      </div>
                      
                      <div className="flex flex-wrap gap-1">
                        {pattern.indicators.map((indicator, idx) => (
                          <span key={idx} className="px-2 py-1 bg-purple-500/20 text-purple-400 rounded-full text-xs">
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Insights */}
              {behaviourData.insights.length > 0 && (
                <div>
                  <div className="text-sm text-cyan-400 mb-3">Behavioral Insights</div>
                  <div className="space-y-2">
                    {behaviourData.insights.map((insight, i) => (
                      <div key={i} className="bg-blue-500/10 rounded p-2 text-xs text-blue-300 border-l-2 border-blue-500">
                        {insight}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk Factors */}
              {behaviourData.riskFactors.length > 0 && (
                <div>
                  <div className="text-sm text-red-400 mb-3">Risk Factors</div>
                  <div className="space-y-2">
                    {behaviourData.riskFactors.map((risk, i) => (
                      <div key={i} className="bg-red-500/10 rounded p-2 text-xs text-red-300 border-l-2 border-red-500">
                        ⚠️ {risk}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              <div>
                <div className="text-sm text-cyan-400 mb-3">Recommendations</div>
                <div className="space-y-2">
                  {behaviourData.recommendations.map((rec, i) => (
                    <div key={i} className="bg-green-500/10 rounded p-2 text-xs text-green-300 border-l-2 border-green-500">
                      💡 {rec}
                    </div>
                  ))}
                </div>
              </div>

              {/* Activity Timeline */}
              {behaviourData.timelineData.length > 0 && (
                <div>
                  <div className="text-sm text-cyan-400 mb-3">Recent Activity Timeline</div>
                  <div className="space-y-2 max-h-32 overflow-y-auto">
                    {behaviourData.timelineData.map((event, i) => (
                      <div key={i} className="flex items-center gap-3 text-xs">
                        <span className="text-gray-400 w-16">{event.time}</span>
                        <div className="w-2 h-2 bg-cyan-500 rounded-full"></div>
                        <span className="text-white flex-1">{event.event}</span>
                        <span className="text-cyan-400">{event.type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </Card>

      {logs.length > 0 && <LiveLogTerminal logs={logs} title="Behaviour Analysis Logs" />}
    </div>
  );
}