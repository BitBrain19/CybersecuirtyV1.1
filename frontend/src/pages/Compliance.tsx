import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import mlService from '@/services/mlService';
import { CheckCircle, XCircle, AlertTriangle, ShieldCheck } from 'lucide-react';

interface ComplianceResult {
  score: number;
  status: string;
  issues: string[];
  compliant: boolean;
  framework: string;
}

const Compliance: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [framework, setFramework] = useState<string>('NIST');
  const [result, setResult] = useState<ComplianceResult | null>(null);
  const { toast } = useToast();

  const fetchCompliance = async (selectedFramework: string) => {
    try {
      setLoading(true);
      const data = await mlService.assessCompliance(selectedFramework);
      setResult(data);
    } catch (error) {
      console.error('Error fetching compliance:', error);
      toast({
        title: 'Error',
        description: 'Failed to assess compliance. Please try again later.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCompliance(framework);
  }, [framework]);

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'compliant':
        return 'bg-green-500/10 text-green-500 border-green-500/20';
      case 'non_compliant':
        return 'bg-red-500/10 text-red-500 border-red-500/20';
      case 'warning':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      default:
        return 'bg-slate-500/10 text-slate-500 border-slate-500/20';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-500';
    if (score >= 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <div className="flex items-center space-x-3">
          <ShieldCheck className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Compliance Assessment</h1>
            <p className="text-sm text-muted-foreground">Verify system adherence to security standards</p>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <Select value={framework} onValueChange={setFramework}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Select Framework" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="NIST">NIST 800-53</SelectItem>
              <SelectItem value="PCI-DSS">PCI-DSS</SelectItem>
              <SelectItem value="HIPAA">HIPAA</SelectItem>
              <SelectItem value="GDPR">GDPR</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={() => fetchCompliance(framework)}>Re-Assess</Button>
        </div>
      </div>

      {loading ? (
        <div className="grid gap-6 md:grid-cols-2">
          <Skeleton className="h-[300px] w-full" />
          <Skeleton className="h-[300px] w-full" />
        </div>
      ) : result ? (
        <div className="grid gap-6 md:grid-cols-2">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Overall Status</CardTitle>
              <CardDescription>Compliance score for {result.framework}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col items-center justify-center py-6">
              <div className="relative flex items-center justify-center">
                <svg className="h-40 w-40 transform -rotate-90">
                  <circle
                    className="text-slate-800"
                    strokeWidth="12"
                    stroke="currentColor"
                    fill="transparent"
                    r="70"
                    cx="80"
                    cy="80"
                  />
                  <circle
                    className={getScoreColor(result.score)}
                    strokeWidth="12"
                    strokeDasharray={440}
                    strokeDashoffset={440 - (440 * result.score) / 100}
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="transparent"
                    r="70"
                    cx="80"
                    cy="80"
                  />
                </svg>
                <div className="absolute flex flex-col items-center">
                  <span className={`text-4xl font-bold ${getScoreColor(result.score)}`}>
                    {Math.round(result.score)}%
                  </span>
                  <span className="text-xs text-muted-foreground">Score</span>
                </div>
              </div>
              
              <div className="mt-6">
                <Badge className={`px-4 py-1 text-lg ${getStatusColor(result.status)}`}>
                  {result.status.replace('_', ' ').toUpperCase()}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Issues & Findings</CardTitle>
              <CardDescription>
                {result.issues.length} issues found requiring attention
              </CardDescription>
            </CardHeader>
            <CardContent>
              {result.issues.length > 0 ? (
                <div className="space-y-4">
                  {result.issues.map((issue, index) => (
                    <div key={index} className="flex items-start space-x-3 p-3 rounded-lg bg-red-500/5 border border-red-500/10">
                      <XCircle className="h-5 w-5 text-red-500 mt-0.5" />
                      <span className="text-sm">{issue}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-[200px] text-center">
                  <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
                  <h3 className="text-lg font-medium">No Issues Found</h3>
                  <p className="text-muted-foreground">System is fully compliant with {result.framework}</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ) : (
        <div className="text-center py-10">
          <p className="text-muted-foreground">Select a framework to start assessment</p>
        </div>
      )}
    </div>
  );
};

export default Compliance;
