import React, { useState, useEffect } from "react";
import Button from "@/components/Button";
import Card from "@/components/Card";
import DataTable from "@/components/DataTable";
import { useToast } from "@/hooks/useToast";
import mlService from "@/services/mlService";

interface Endpoint {
  id: string;
  hostname: string;
  ip_address: string;
  os: string;
  status: "online" | "offline" | "disconnected";
  agent_version: string;
  last_seen: string;
  risk_level: "low" | "medium" | "high" | "critical";
}

interface Alert {
  id: string;
  endpoint_id: string;
  hostname: string;
  alert_type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  timestamp: string;
  status: "open" | "investigating" | "resolved";
}

const EDR: React.FC = () => {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(
    null
  );
  const { success, error } = useToast();



  // Fetch endpoints
  useEffect(() => {
    const fetchEndpoints = async () => {
      try {
        setLoading(true);
        const data = await mlService.getEndpoints();
        setEndpoints(data || []);
        success("Endpoints loaded");
      } catch (err) {
        error(err instanceof Error ? err.message : "Failed to load endpoints");
      } finally {
        setLoading(false);
      }
    };

    fetchEndpoints();
  }, []);

  // Fetch alerts for selected endpoint or all alerts
  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const data = await mlService.getEDRAlerts(selectedEndpoint?.id);
        setAlerts(data || []);
      } catch (err) {
        error(err instanceof Error ? err.message : "Failed to load alerts");
      }
    };

    fetchAlerts();
  }, [selectedEndpoint]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online":
        return "bg-green-100 text-green-800";
      case "offline":
        return "bg-gray-100 text-gray-800";
      case "disconnected":
        return "bg-red-100 text-red-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800";
      case "high":
        return "bg-orange-100 text-orange-800";
      case "medium":
        return "bg-yellow-100 text-yellow-800";
      case "low":
        return "bg-green-100 text-green-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const endpointColumns = [
    { key: "hostname" as const, label: "Hostname", sortable: true },
    { key: "ip_address" as const, label: "IP Address" },
    { key: "os" as const, label: "Operating System" },
    {
      key: "status" as const,
      label: "Status",
      render: (value: any) => (
        <span
          className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(
            value
          )}`}
        >
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </span>
      ),
    },
    { key: "agent_version" as const, label: "Agent Version" },
    { key: "last_seen" as const, label: "Last Seen" },
  ];

  const alertColumns = [
    { key: "hostname" as const, label: "Endpoint", sortable: true },
    { key: "alert_type" as const, label: "Alert Type" },
    {
      key: "severity" as const,
      label: "Severity",
      render: (value: any) => (
        <span
          className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(
            value
          )}`}
        >
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </span>
      ),
    },
    { key: "description" as const, label: "Description" },
    { key: "timestamp" as const, label: "Detected" },
    {
      key: "status" as const,
      label: "Status",
      render: (value: any) => (
        <span className="px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </span>
      ),
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            EDR Dashboard
          </h1>
          <p className="text-gray-600">Endpoint Detection and Response</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                Total Endpoints
              </p>
              <p className="text-3xl font-bold text-blue-600 mt-2">
                {endpoints.length}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">Online</p>
              <p className="text-3xl font-bold text-green-600 mt-2">
                {endpoints.filter((e) => e.status === "online").length}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                Critical Alerts
              </p>
              <p className="text-3xl font-bold text-red-600 mt-2">
                {alerts.filter((a) => a.severity === "critical").length}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">Open Alerts</p>
              <p className="text-3xl font-bold text-orange-600 mt-2">
                {alerts.filter((a) => a.status === "open").length}
              </p>
            </div>
          </Card>
        </div>

        {/* Endpoints */}
        <Card shadow="md" padding="lg" className="mb-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-gray-900">Endpoints</h2>
            <Button
              variant="primary"
              size="sm"
              onClick={() => window.location.reload()}
            >
              Refresh
            </Button>
          </div>

          <DataTable
            data={endpoints}
            columns={endpointColumns}
            loading={loading}
            hover
            onRowClick={(row) => setSelectedEndpoint(row)}
          />
        </Card>

        {/* Alerts */}
        <Card shadow="md" padding="lg">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl font-bold text-gray-900">
                {selectedEndpoint
                  ? `Alerts for ${selectedEndpoint.hostname}`
                  : "All Alerts"}
              </h2>
            </div>
            {selectedEndpoint && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setSelectedEndpoint(null)}
              >
                Clear Filter
              </Button>
            )}
          </div>

          <DataTable data={alerts} columns={alertColumns} hover />
        </Card>
      </div>
    </div>
  );
};

export default EDR;
