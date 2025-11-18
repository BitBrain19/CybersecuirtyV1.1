import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Calendar } from '@/components/ui/calendar';
import { DateRange } from 'react-day-picker';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { useToast } from '@/hooks/use-toast';
import { fetchReports, generateReport, Report } from '@/services/reportService';
import { ReportType, ReportStatus } from '@/types';
import { formatDate } from '@/utils/helpers';
import ShieldLogo from '@/assets/shield-logo.svg';
import { CalendarIcon } from '@/components/icons';

const Reports: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [reports, setReports] = useState<Report[]>([]);
  const [activeTab, setActiveTab] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [dateRange, setDateRange] = useState<DateRange>({ from: undefined, to: undefined });
  const [generatingReport, setGeneratingReport] = useState<boolean>(false);
  const [newReportType, setNewReportType] = useState<string>('vulnerability');
  const { toast } = useToast();

  useEffect(() => {
    loadReports();
  }, [activeTab, typeFilter, dateRange]);

  const loadReports = async () => {
    try {
      setLoading(true);
      const data = await fetchReports({
        status: activeTab !== 'all' ? activeTab : undefined,
        type: typeFilter !== 'all' ? typeFilter : undefined,
        search: searchQuery || undefined,
        startDate: dateRange.from ? dateRange.from.toISOString() : undefined,
        endDate: dateRange.to ? dateRange.to.toISOString() : undefined,
      });
      setReports(data);
    } catch (error) {
      console.error('Failed to fetch reports:', error);
      toast({
        title: 'Error',
        description: 'Failed to load reports. Please try again later.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    loadReports();
  };

  const handleGenerateReport = async () => {
    try {
      setGeneratingReport(true);
      await generateReport({
        type: newReportType as ReportType,
      });
      toast({
        title: 'Success',
        description: 'Report generation has been initiated. You will be notified when it is complete.',
      });
      loadReports(); // Reload to show the new pending report
    } catch (error) {
      console.error('Failed to generate report:', error);
      toast({
        title: 'Error',
        description: 'Failed to generate report. Please try again later.',
        variant: 'destructive',
      });
    } finally {
      setGeneratingReport(false);
    }
  };

  const getStatusBadge = (status: ReportStatus) => {
    switch (status) {
      case 'completed':
        return <Badge variant="success">Completed</Badge>;
      case 'pending':
        return <Badge variant="outline">Pending</Badge>;
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>;
      case 'generating':
        return <Badge variant="secondary">Generating</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const getReportTypeLabel = (type: ReportType) => {
    switch (type) {
      case 'vulnerability':
        return 'Vulnerability Report';
      case 'compliance':
        return 'Compliance Report';
      case 'security_posture':
        return 'Security Posture Report';
      case 'attack_surface':
        return 'Attack Surface Report';
      case 'incident':
        return 'Incident Report';
      default:
        return type;
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <div className="flex items-center space-x-3">
          <img src={ShieldLogo} alt="SecurityAI" className="h-8 w-8" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Security Reports</h1>
            <p className="text-sm text-muted-foreground">Generate executive and compliance insights</p>
          </div>
        </div>
        <div className="flex space-x-2">
          <Select value={newReportType} onValueChange={setNewReportType}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Report Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="vulnerability">Vulnerability Report</SelectItem>
              <SelectItem value="compliance">Compliance Report</SelectItem>
              <SelectItem value="security_posture">Security Posture Report</SelectItem>
              <SelectItem value="attack_surface">Attack Surface Report</SelectItem>
              <SelectItem value="incident">Incident Report</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={handleGenerateReport} disabled={generatingReport}>
            {generatingReport ? 'Generating...' : 'Generate Report'}
          </Button>
        </div>
      </div>

      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Filter Reports</CardTitle>
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
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger>
                  <SelectValue placeholder="Report Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="vulnerability">Vulnerability</SelectItem>
                  <SelectItem value="compliance">Compliance</SelectItem>
                  <SelectItem value="security_posture">Security Posture</SelectItem>
                  <SelectItem value="attack_surface">Attack Surface</SelectItem>
                  <SelectItem value="incident">Incident</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="w-full md:w-[240px]">
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    className="w-full justify-start text-left font-normal"
                  >
                    <CalendarIcon className="mr-2 h-4 w-4" />
                    {dateRange.from ? (
                      dateRange.to ? (
                        <>
                          {formatDate(dateRange.from)} - {formatDate(dateRange.to)}
                        </>
                      ) : (
                        formatDate(dateRange.from)
                      )
                    ) : (
                      <span>Pick a date range</span>
                    )}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="start">
                  <Calendar
                    initialFocus
                    mode="range"
                    defaultMonth={dateRange.from}
                    selected={dateRange}
                    onSelect={(range) => range && setDateRange(range)}
                    numberOfMonths={2}
                    required={false}
                  /> 
                </PopoverContent>
              </Popover>
            </div>
            <Button onClick={handleSearch}>Search</Button>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="all">All Reports</TabsTrigger>
          <TabsTrigger value="completed">Completed</TabsTrigger>
          <TabsTrigger value="generating">Generating</TabsTrigger>
          <TabsTrigger value="pending">Pending</TabsTrigger>
          <TabsTrigger value="failed">Failed</TabsTrigger>
        </TabsList>

        <TabsContent value={activeTab} className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Report List</CardTitle>
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
              ) : reports.length > 0 ? (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Report Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Generated At</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {reports.map((report) => (
                        <TableRow key={report.id}>
                          <TableCell className="font-medium">{report.name}</TableCell>
                          <TableCell>{getReportTypeLabel(report.type as ReportType)}</TableCell>
                          <TableCell>{formatDate(report.generatedAt)}</TableCell>
                          <TableCell>{getStatusBadge(report.status as ReportStatus)}</TableCell>
                          <TableCell>
                            <div className="flex space-x-2">
                              {report.status === 'completed' && (
                                <>
                                  <Button variant="outline" size="sm">
                                    View
                                  </Button>
                                  <Button variant="outline" size="sm">
                                    Download
                                  </Button>
                                </>
                              )}
                              {report.status === 'failed' && (
                                <Button variant="outline" size="sm" onClick={() => handleGenerateReport()}>
                                  Retry
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="text-center py-10">
                  <p className="text-muted-foreground">No reports found matching your criteria</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Reports;