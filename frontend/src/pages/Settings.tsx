import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
// import { useAuth } from '@/hooks/useAuth'; // Not needed
import { fetchUserSettings, updateUserSettings } from '@/services/settingsService';
import { UserSettings, NotificationPreferences, ThemePreference } from '@/types';
import { applyTheme } from '@/utils/theme';

const Settings: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<string>('profile');
  const [settings, setSettings] = useState<UserSettings | null>(null);
  const { toast } = useToast();
  // const { user } = useAuth(); // Commented out as it's not being used

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const data = await fetchUserSettings();
      setSettings(data);
    } catch (error) {
      console.error('Failed to fetch settings:', error);
      toast({
        title: 'Error',
        description: 'Failed to load settings. Please try again later.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async () => {
    if (!settings) return;
    
    try {
      setSaving(true);
      await updateUserSettings(settings);
      toast({
        title: 'Success',
        description: 'Settings have been saved successfully.',
      });
    } catch (error) {
      console.error('Failed to save settings:', error);
      toast({
        title: 'Error',
        description: 'Failed to save settings. Please try again later.',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!settings) return;
    
    const { name, value } = e.target;
    setSettings((prev: any) => {
      if (!prev) return prev;
      return { ...prev, [name]: value };
    });
  };

  const handleNotificationChange = (key: keyof NotificationPreferences, value: boolean) => {
    if (!settings) return;
    
    setSettings((prev: any) => {
      if (!prev) return prev;
      return {
        ...prev,
        notificationPreferences: {
          ...prev.notificationPreferences,
          [key]: value
        }
      };
    });
  };

  const handleThemeChange = (theme: ThemePreference) => {
    if (!settings) return;
    
    setSettings((prev: any) => {
      if (!prev) return prev;
      return {
        ...prev,
        theme
      };
    });

    // Apply immediately and persist
    applyTheme(theme)
  };

  const handleApiKeyRegenerate = () => {
    toast({
      title: 'API Key',
      description: 'New API key has been generated.',
    });
    // In a real app, this would call an API to regenerate the key
    setSettings((prev: any) => {
      if (!prev) return prev;
      return {
        ...prev,
        apiKey: `sk_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`
      };
    });
  };

  if (loading) {
    return (
      <div className="p-6 space-y-6">
        <h1 className="text-3xl font-bold">Settings</h1>
        <div className="space-y-4">
          <Skeleton className="h-8 w-[200px]" />
          <Skeleton className="h-[400px] w-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <h1 className="text-3xl font-bold">Settings</h1>
        <Button onClick={handleSaveSettings} disabled={saving}>
          {saving ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
          <TabsTrigger value="api">API</TabsTrigger>
        </TabsList>

        <TabsContent value="profile" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
              <CardDescription>Update your personal information</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Full Name</Label>
                  <Input 
                    id="name" 
                    name="name" 
                    value={settings?.name || ''} 
                    onChange={handleInputChange} 
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email Address</Label>
                  <Input 
                    id="email" 
                    name="email" 
                    type="email" 
                    value={settings?.email || ''} 
                    onChange={handleInputChange} 
                    disabled={true} 
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="jobTitle">Job Title</Label>
                  <Input 
                    id="jobTitle" 
                    name="jobTitle" 
                    value={settings?.jobTitle || ''} 
                    onChange={handleInputChange} 
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="department">Department</Label>
                  <Input 
                    id="department" 
                    name="department" 
                    value={settings?.department || ''} 
                    onChange={handleInputChange} 
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Password</CardTitle>
              <CardDescription>Update your password</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="currentPassword">Current Password</Label>
                  <Input id="currentPassword" name="currentPassword" type="password" />
                </div>
                <div></div>
                <div className="space-y-2">
                  <Label htmlFor="newPassword">New Password</Label>
                  <Input id="newPassword" name="newPassword" type="password" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm New Password</Label>
                  <Input id="confirmPassword" name="confirmPassword" type="password" />
                </div>
              </div>
              <Button variant="outline">Change Password</Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Notification Preferences</CardTitle>
              <CardDescription>Configure how you want to be notified</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">Security Alerts</h4>
                    <p className="text-sm text-muted-foreground">Receive notifications for critical security alerts</p>
                  </div>
                  <Switch 
                    checked={settings?.notificationPreferences?.securityAlerts || false} 
                    onCheckedChange={(checked: boolean) => handleNotificationChange('securityAlerts', checked)} 
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">Vulnerability Updates</h4>
                    <p className="text-sm text-muted-foreground">Receive notifications for new vulnerabilities</p>
                  </div>
                  <Switch 
                    checked={settings?.notificationPreferences?.vulnerabilityUpdates || false} 
                    onCheckedChange={(checked: boolean) => handleNotificationChange('vulnerabilityUpdates', checked)} 
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">Report Completion</h4>
                    <p className="text-sm text-muted-foreground">Receive notifications when reports are completed</p>
                  </div>
                  <Switch 
                    checked={settings?.notificationPreferences?.reportCompletion || false} 
                    onCheckedChange={(checked: boolean) => handleNotificationChange('reportCompletion', checked)} 
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium">System Updates</h4>
                    <p className="text-sm text-muted-foreground">Receive notifications for system updates and maintenance</p>
                  </div>
                  <Switch 
                    checked={settings?.notificationPreferences?.systemUpdates || false} 
                    onCheckedChange={(checked: boolean) => handleNotificationChange('systemUpdates', checked)} 
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="notificationEmail">Notification Email</Label>
                <Input 
                  id="notificationEmail" 
                  name="notificationEmail" 
                  type="email" 
                  value={settings?.notificationEmail || ''} 
                  onChange={handleInputChange} 
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="appearance" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Theme Settings</CardTitle>
              <CardDescription>Customize the appearance of the application</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label>Theme Mode</Label>
                <div className="flex space-x-4">
                  <div className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      id="light" 
                      name="theme" 
                      value="light" 
                      checked={settings?.theme === 'light'} 
                      onChange={() => handleThemeChange('light')} 
                    />
                    <Label htmlFor="light">Light</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      id="dark" 
                      name="theme" 
                      value="dark" 
                      checked={settings?.theme === 'dark'} 
                      onChange={() => handleThemeChange('dark')} 
                    />
                    <Label htmlFor="dark">Dark</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <input 
                      type="radio" 
                      id="system" 
                      name="theme" 
                      value="system" 
                      checked={settings?.theme === 'system'} 
                      onChange={() => handleThemeChange('system')} 
                    />
                    <Label htmlFor="system">System</Label>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="density">Interface Density</Label>
                <Select 
                  value={settings?.interfaceDensity || 'normal'} 
                  onValueChange={(value: string) => {
                    setSettings((prev: any) => {
                      if (!prev) return prev;
                      return { ...prev, interfaceDensity: value };
                    });
                  }}
                >
                  <SelectTrigger id="density">
                    <SelectValue placeholder="Select density" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="compact">Compact</SelectItem>
                    <SelectItem value="normal">Normal</SelectItem>
                    <SelectItem value="comfortable">Comfortable</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-medium">Animations</h4>
                  <p className="text-sm text-muted-foreground">Enable or disable UI animations</p>
                </div>
                <Switch 
                  checked={settings?.animationsEnabled || false} 
                  onCheckedChange={(checked: boolean) => {
                    setSettings((prev: any) => {
                      if (!prev) return prev;
                      return { ...prev, animationsEnabled: checked };
                    });
                  }} 
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="api" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>API Access</CardTitle>
              <CardDescription>Manage your API keys and access</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="apiKey">API Key</Label>
                <div className="flex space-x-2">
                  <Input 
                    id="apiKey" 
                    value={settings?.apiKey || ''} 
                    readOnly 
                    className="font-mono" 
                  />
                  <Button variant="outline" onClick={handleApiKeyRegenerate}>
                    Regenerate
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  This API key provides full access to your account. Keep it secure and do not share it.
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">API Usage</h4>
                <p className="text-sm text-muted-foreground">
                  Current usage: {settings?.apiUsage?.current || 0} / {settings?.apiUsage?.limit || 1000} requests this month
                </p>
                <div className="w-full bg-secondary h-2 rounded-full overflow-hidden">
                  <div 
                    className="bg-primary h-full" 
                    style={{ 
                      width: `${Math.min(100, ((settings?.apiUsage?.current || 0) / (settings?.apiUsage?.limit || 1000)) * 100)}%` 
                    }}
                  ></div>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">Webhook URL</h4>
                <Input 
                  id="webhookUrl" 
                  name="webhookUrl" 
                  value={settings?.webhookUrl || ''} 
                  onChange={handleInputChange} 
                  placeholder="https://your-server.com/webhook" 
                />
                <p className="text-sm text-muted-foreground">
                  Receive real-time notifications via webhook when security events occur
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Settings;