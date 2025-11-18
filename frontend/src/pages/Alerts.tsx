import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { CustomPagination } from '@/components/ui/custom-pagination';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import { fetchAlerts, dismissAlert, acknowledgeAlert } from '@/services/alertService';
import { Alert, AlertSeverity, AlertStatus } from '@/types';
import { formatDate, getSeverityColor } from '@/utils/helpers';
import { ITEMS_PER_PAGE } from '@/utils/constants';
import AlertLogo from '@/assets/triangle-alert.svg';

const Alerts: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const { toast } = useToast();

  useEffect(() => {
    loadAlerts();
  }, [currentPage, severityFilter, statusFilter]);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const response = await fetchAlerts(
        currentPage,
        ITEMS_PER_PAGE,
        {
          severity: severityFilter !== 'all' ? [severityFilter] : undefined,
          status: statusFilter !== 'all' ? [statusFilter] : undefined,
          search: searchQuery || undefined,
        }
      );
      
      setAlerts(response.alerts);
      setTotalPages(Math.ceil(response.total / ITEMS_PER_PAGE));
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
      toast({
        title: 'Error',
        description: 'Failed to load alerts. Please try again later.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setCurrentPage(1); // Reset to first page when searching
    loadAlerts();
  };

  const handleDismiss = async (alertId: string) => {
    try {
      await dismissAlert(alertId);
      toast({
        title: 'Success',
        description: 'Alert has been dismissed',
      });
      loadAlerts(); // Reload the alerts
    } catch (error) {
      console.error('Failed to dismiss alert:', error);
      toast({
        title: 'Error',
        description: 'Failed to dismiss alert. Please try again.',
        variant: 'destructive',
      });
    }
  };

  const handleAcknowledge = async (alertId: string) => {
    try {
      await acknowledgeAlert(alertId);
      toast({
        title: 'Success',
        description: 'Alert has been acknowledged',
      });
      loadAlerts(); // Reload the alerts
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
      toast({
        title: 'Error',
        description: 'Failed to acknowledge alert. Please try again.',
        variant: 'destructive',
      });
    }
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'new':
        return <Badge variant="destructive">New</Badge>;
      case 'acknowledged':
        return <Badge variant="outline">Acknowledged</Badge>;
      case 'dismissed':
        return <Badge variant="secondary">Dismissed</Badge>;
      case 'resolved':
        return <Badge variant="success">Resolved</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
       <div className="flex items-center space-x-3">
          <img src={AlertLogo} alt="SecurityAI" className="h-8 w-8" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Alert</h1>
          </div>
        </div>
        <Button
          onClick={() => {
            setCurrentPage(1);
            loadAlerts();
          }}
        >
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filter Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <Input
                placeholder="Search by title or description"
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
            <div className="w-full md:w-[180px]">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger>
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="new">New</SelectItem>
                  <SelectItem value="acknowledged">Acknowledged</SelectItem>
                  <SelectItem value="dismissed">Dismissed</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleSearch}>Search</Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Alert List</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-4">
              {Array(5).fill(0).map((_, i) => (
                <div key={i} className="flex items-center space-x-4">
                  <Skeleton className="h-12 w-12 rounded-full" />
                  <div className="space-y-2">
                    <Skeleton className="h-4 w-[250px]" />
                    <Skeleton className="h-4 w-[200px]" />
                  </div>
                </div>
              ))}
            </div>
          ) : alerts.length > 0 ? (
            <>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Detected At</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell>
                          <Badge 
                            variant="outline" 
                            style={{ backgroundColor: getSeverityColor(alert.severity as AlertSeverity) }}
                          >
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium">{alert.title}</TableCell>
                        <TableCell>{alert.source}</TableCell>
                        <TableCell>{formatDate(alert.timestamp)}</TableCell>
                        <TableCell>{getStatusBadge(alert.status as AlertStatus)}</TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            {alert.status === 'new' && (
                              <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={() => handleAcknowledge(alert.id)}
                              >
                                Acknowledge
                              </Button>
                            )}
                            {(alert.status === 'new' || alert.status === 'acknowledged') && (
                              <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={() => handleDismiss(alert.id)}
                              >
                                Dismiss
                              </Button>
                            )}
                            <Button variant="outline" size="sm">
                              Details
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>

              <div className="flex items-center justify-center space-x-2 py-4">
                <CustomPagination
                  currentPage={currentPage}
                  totalPages={totalPages}
                  onPageChange={setCurrentPage}
                />
              </div>
            </>
          ) : (
            <div className="text-center py-10">
              <p className="text-muted-foreground">No alerts found matching your criteria</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default Alerts;