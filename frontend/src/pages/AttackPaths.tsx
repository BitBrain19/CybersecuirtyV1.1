import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import mlService from '@/services/mlService';
import { AttackPathSeverity } from '@/types';
import { formatDate, getSeverityColor } from '@/utils/helpers';
import NetworkLogo from '@/assets/network.svg';

// Define types locally for now if missing
interface AttackPath {
  id: string;
  name: string;
  description: string;
  severity: string;
  discoveredAt?: string;
  created_at?: string;
  nodeCount: number;
  edgeCount: number;
  nodes: any[];
  edges: any[];
}

const AttackPaths: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [activeTab, setActiveTab] = useState<string>('graph');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const { toast } = useToast();

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const data = await mlService.getAttackPaths();
        // Backend returns a single graph or list of paths. 
        // Adapting to list format for UI
        const paths = Array.isArray(data) ? data : [data];
        
        // Filter data client-side based on severity and search query
        const filteredData = paths.filter((path: any) => {
          const matchesSeverity = severityFilter === 'all' || path.severity === severityFilter;
          const matchesSearch = !searchQuery || 
            (path.name && path.name.toLowerCase().includes(searchQuery.toLowerCase())) || 
            (path.description && path.description.toLowerCase().includes(searchQuery.toLowerCase()));
          return matchesSeverity && matchesSearch;
        });
        setAttackPaths(filteredData);
      } catch (error) {
        console.error('Error fetching attack paths:', error);
        toast({
          title: 'Error',
          description: 'Failed to load attack paths. Please try again later.',
          variant: 'destructive',
        });
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [severityFilter, searchQuery]);

  const handleSearch = () => {
    // Search is now handled by the useEffect dependency on searchQuery
  };

  const filteredAttackPaths = attackPaths;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <div className="flex items-center space-x-3">
          <img src={NetworkLogo} alt="SecurityAI" className="h-8 w-8" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Attack Paths</h1>
            <p className="text-sm text-muted-foreground">Visualize routes and disrupt risks</p>
          </div>
        </div>
        <Button
          onClick={() => {
            // Re-fetch logic
            window.location.reload(); 
          }}
        >
          Refresh
        </Button>
      </div>

      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Filter Attack Paths</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <Input
                placeholder="Search by name or description"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              />
            </div>
            <div className="w-full md:w-[180px]">
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger>
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleSearch}>Search</Button>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="graph">Graph View</TabsTrigger>
          <TabsTrigger value="list">List View</TabsTrigger>
        </TabsList>

        <TabsContent value="graph" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Attack Path Visualization</CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="h-[600px] w-full">
                  <Skeleton className="h-full w-full" />
                </div>
              ) : filteredAttackPaths.length > 0 ? (
                <div className="h-[600px] w-full border rounded-md p-4 flex items-center justify-center bg-slate-900">
                  {/* Simple SVG Visualization of the first path */}
                  <svg width="100%" height="100%" viewBox="0 0 800 600">
                    <defs>
                      <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="20" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
                      </marker>
                    </defs>
                    {/* Placeholder Nodes - in real app would calculate layout */}
                    <circle cx="100" cy="300" r="20" fill="#ef4444" />
                    <text x="100" y="340" textAnchor="middle" fill="white" fontSize="12">Attacker</text>
                    
                    <line x1="120" y1="300" x2="380" y2="300" stroke="#64748b" strokeWidth="2" markerEnd="url(#arrowhead)" />
                    
                    <circle cx="400" cy="300" r="20" fill="#3b82f6" />
                    <text x="400" y="340" textAnchor="middle" fill="white" fontSize="12">Compromised Host</text>
                    
                    <line x1="420" y1="300" x2="680" y2="300" stroke="#64748b" strokeWidth="2" markerEnd="url(#arrowhead)" />
                    
                    <circle cx="700" cy="300" r="20" fill="#22c55e" />
                    <text x="700" y="340" textAnchor="middle" fill="white" fontSize="12">Target DB</text>
                  </svg>
                </div>
              ) : (
                <div className="text-center py-10">
                  <p className="text-muted-foreground">No attack paths found matching your criteria</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="list" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Attack Path List</CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="space-y-4">
                  {Array(3).fill(0).map((_, i) => (
                    <Card key={i} className="glass-card">
                      <CardHeader>
                        <Skeleton className="h-5 w-1/3" />
                      </CardHeader>
                      <CardContent>
                        <Skeleton className="h-4 w-full mb-2" />
                        <Skeleton className="h-4 w-2/3" />
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : filteredAttackPaths.length > 0 ? (
                <div className="space-y-4">
                  {filteredAttackPaths.map((path) => (
                    <Card key={path.id} className="glass-card">
                      <CardHeader className="pb-2">
                        <div className="flex justify-between items-center">
                          <CardTitle className="text-lg">{path.name}</CardTitle>
                          <Badge 
                            variant="outline" 
                            style={{ backgroundColor: getSeverityColor(path.severity as AttackPathSeverity) }}
                          >
                            {path.severity}
                          </Badge>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <p className="text-sm text-muted-foreground mb-2">{path.description}</p>
                        <div className="flex flex-wrap gap-2 mt-2">
                          <div className="text-xs text-muted-foreground">
                            <span className="font-semibold">Discovered:</span> {path.discoveredAt ? formatDate(path.discoveredAt) : formatDate(path.created_at)}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            <span className="font-semibold">Nodes:</span> {path.nodeCount}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            <span className="font-semibold">Edges:</span> {path.edgeCount}
                          </div>
                        </div>
                        <div className="flex space-x-2 mt-4">
                          <Button size="sm" variant="outline">View Details</Button>
                          <Button size="sm" variant="outline">Remediation Steps</Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : (
                <div className="text-center py-10">
                  <p className="text-muted-foreground">No attack paths found matching your criteria</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AttackPaths;