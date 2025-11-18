import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { LineChart, PieChart } from '@/components/charts';
import { Alert } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import { fetchDashboardData } from '@/services/dashboardService';
import { DashboardData, AlertSeverity } from '@/types';
import { formatDate, getSeverityColor } from '@/utils/helpers';
import ShieldLogo from '@/assets/shield-logo.svg';

const Dashboard: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const { toast } = useToast();

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        setLoading(true);
        const data = await fetchDashboardData();
        setDashboardData(data);
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
        toast({
          title: 'Error',
          description: 'Failed to load dashboard data. Please try again later.',
          variant: 'destructive',
        });
      } finally {
        setLoading(false);
      }
    };

    loadDashboardData();

    // Refresh data every 5 minutes
    const intervalId = setInterval(loadDashboardData, 5 * 60 * 1000);
    return () => clearInterval(intervalId);
  }, [toast]);

  if (loading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center space-x-3">
          <img src={ShieldLogo} alt="SecurityAI" className="h-8 w-8" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
            <p className="text-sm text-muted-foreground">Apple-inspired, clean and focused insights</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {Array(4).fill(0).map((_, i) => (
            <Card key={i} className="w-full glass-card">
              <CardHeader>
                <Skeleton className="h-4 w-1/2" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-20 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <Skeleton className="h-4 w-1/3" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-[300px] w-full" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <Skeleton className="h-4 w-1/3" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-[300px] w-full" />
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <div className="flex items-center space-x-3">
          <img src={ShieldLogo} alt="SecurityAI" className="h-8 w-8" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
            <p className="text-sm text-muted-foreground">Adaptive cybersecurity overview</p>
          </div>
        </div>
        <Button
          onClick={() => {
            toast({
              title: 'Refreshing',
              description: 'Dashboard data is being refreshed',
            });
            // Implement refresh logic
          }}
        >
          Refresh Data
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Total Alerts</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{dashboardData?.alertsCount || 0}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  +{dashboardData?.alertsTrend || 0}% from last week
                </p>
              </CardContent>
            </Card>
            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Critical Vulnerabilities</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-red-500">{dashboardData?.criticalVulnerabilities || 0}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {dashboardData?.vulnerabilitiesTrend || 0}% from last week
                </p>
              </CardContent>
            </Card>
            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Attack Paths</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{dashboardData?.attackPathsCount || 0}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {dashboardData?.attackPathsTrend || 0}% from last week
                </p>
              </CardContent>
            </Card>
            <Card className="glass-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">Security Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{dashboardData?.securityScore || 0}/100</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {dashboardData?.securityScoreTrend || 0}% from last week
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="glass-card">
              <CardHeader>
                <CardTitle>Alerts Over Time</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-[300px]">
                  <LineChart 
                    data={dashboardData?.alertsOverTime || []} 
                    xKey="date" 
                    yKey="count" 
                    categories={['Critical', 'High', 'Medium', 'Low']} 
                  />
                </div>
              </CardContent>
            </Card>
            <Card className="glass-card">
              <CardHeader>
                <CardTitle>Vulnerability Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-[300px]">
                  <PieChart 
                    data={dashboardData?.vulnerabilityDistribution || []} 
                    nameKey="severity" 
                    valueKey="count" 
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Alerts */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Recent Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {dashboardData?.recentAlerts?.length ? (
                  dashboardData.recentAlerts.map((alert, index) => (
                    <Alert key={index} className="flex items-center justify-between">
                      <div>
                        <h4 className="font-semibold">{alert.title}</h4>
                        <p className="text-sm text-muted-foreground">{alert.description}</p>
                        <p className="text-xs text-muted-foreground mt-1">{formatDate(alert.timestamp)}</p>
                      </div>
                      <Badge variant="outline" style={{ backgroundColor: getSeverityColor(alert.severity as AlertSeverity) }}>
                        {alert.severity}
                      </Badge>
                    </Alert>
                  ))
                ) : (
                  <p className="text-muted-foreground">No recent alerts</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats" className="space-y-6">
          {/* Threat Intelligence Content */}
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">Detailed threat intelligence information and analysis</p>
              {/* Threat Intelligence components would go here */}
              <div className="h-[400px] flex items-center justify-center border rounded-md">
                <p className="text-muted-foreground">Threat Intelligence visualization will be displayed here</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vulnerabilities" className="space-y-6">
          {/* Vulnerabilities Content */}
          <Card>
            <CardHeader>
              <CardTitle>Vulnerability Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">Comprehensive vulnerability assessment and management</p>
              {/* Vulnerability components would go here */}
              <div className="h-[400px] flex items-center justify-center border rounded-md">
                <p className="text-muted-foreground">Vulnerability assessment data will be displayed here</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-6">
          {/* Compliance Content */}
          <Card>
            <CardHeader>
              <CardTitle>Compliance Status</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-4">Regulatory compliance status and reports</p>
              {/* Compliance components would go here */}
              <div className="h-[400px] flex items-center justify-center border rounded-md">
                <p className="text-muted-foreground">Compliance reports will be displayed here</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Dashboard;