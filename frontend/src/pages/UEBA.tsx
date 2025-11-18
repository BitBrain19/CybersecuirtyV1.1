import React, { useState, useEffect } from "react";
import Button from "@/components/Button";
import Card from "@/components/Card";
import DataTable from "@/components/DataTable";
import { useToast } from "@/hooks/useToast";

interface UserRiskData {
  user_id: string;
  username: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  anomalies_count: number;
  last_activity: string;
  behavior_baseline: string;
}

interface Anomaly {
  id: string;
  user_id: string;
  username: string;
  anomaly_type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  timestamp: string;
  details?: string;
}

const UEBA: React.FC = () => {
  const [users, setUsers] = useState<UserRiskData[]>([]);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<UserRiskData | null>(null);
  const { success, error } = useToast();

  // Fetch user risk data
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        setLoading(true);
        const response = await fetch(
          `${import.meta.env.VITE_API_URL}/ueba/users`,
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            },
          }
        );

        if (!response.ok) throw new Error("Failed to fetch user data");

        const data = await response.json();
        setUsers(data.users || []);
        success("User risk data loaded");
      } catch (err) {
        error(err instanceof Error ? err.message : "Failed to load user data");
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, []);

  // Fetch anomalies when user is selected
  useEffect(() => {
    const fetchAnomalies = async () => {
      if (!selectedUser) {
        setAnomalies([]);
        return;
      }

      try {
        const response = await fetch(
          `${import.meta.env.VITE_API_URL}/ueba/users/${
            selectedUser.user_id
          }/anomalies`,
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            },
          }
        );

        if (!response.ok) throw new Error("Failed to fetch anomalies");

        const data = await response.json();
        setAnomalies(data.anomalies || []);
      } catch (err) {
        error(err instanceof Error ? err.message : "Failed to load anomalies");
      }
    };

    fetchAnomalies();
  }, [selectedUser]);

  const getRiskLevelColor = (level: string) => {
    switch (level) {
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

  const userColumns = [
    { key: "username" as const, label: "Username", sortable: true },
    {
      key: "risk_score" as const,
      label: "Risk Score",
      sortable: true,
      render: (value: any) => (
        <div className="flex items-center gap-2">
          <div className="w-16 bg-gray-200 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all ${
                value > 80
                  ? "bg-red-600"
                  : value > 60
                  ? "bg-orange-600"
                  : value > 40
                  ? "bg-yellow-600"
                  : "bg-green-600"
              }`}
              style={{ width: `${value}%` }}
            />
          </div>
          <span className="font-medium text-gray-900">{value}</span>
        </div>
      ),
    },
    {
      key: "risk_level" as const,
      label: "Risk Level",
      render: (value: any) => (
        <span
          className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskLevelColor(
            value
          )}`}
        >
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </span>
      ),
    },
    { key: "anomalies_count" as const, label: "Anomalies" },
    { key: "last_activity" as const, label: "Last Activity" },
  ];

  const anomalyColumns = [
    { key: "anomaly_type" as const, label: "Anomaly Type", sortable: true },
    {
      key: "severity" as const,
      label: "Severity",
      render: (value: any) => (
        <span
          className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskLevelColor(
            value
          )}`}
        >
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </span>
      ),
    },
    { key: "description" as const, label: "Description" },
    { key: "timestamp" as const, label: "Detected" },
  ];

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            UEBA Analytics
          </h1>
          <p className="text-gray-600">
            User and Entity Behavior Analytics - Detect anomalous user behavior
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">Total Users</p>
              <p className="text-3xl font-bold text-blue-600 mt-2">
                {users.length}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                High Risk Users
              </p>
              <p className="text-3xl font-bold text-red-600 mt-2">
                {
                  users.filter(
                    (u) =>
                      u.risk_level === "high" || u.risk_level === "critical"
                  ).length
                }
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                Total Anomalies
              </p>
              <p className="text-3xl font-bold text-orange-600 mt-2">
                {users.reduce((acc, u) => acc + u.anomalies_count, 0)}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                Avg Risk Score
              </p>
              <p className="text-3xl font-bold text-purple-600 mt-2">
                {users.length > 0
                  ? Math.round(
                      users.reduce((acc, u) => acc + u.risk_score, 0) /
                        users.length
                    )
                  : 0}
              </p>
            </div>
          </Card>
        </div>

        {/* Users Table */}
        <Card shadow="md" padding="lg" className="mb-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-gray-900">
              User Risk Dashboard
            </h2>
            <Button
              variant="primary"
              size="sm"
              onClick={() => window.location.reload()}
            >
              Refresh
            </Button>
          </div>

          <DataTable
            data={users}
            columns={userColumns}
            loading={loading}
            hover
            onRowClick={(row) => setSelectedUser(row)}
          />
        </Card>

        {/* Anomalies Timeline */}
        {selectedUser && (
          <Card shadow="md" padding="lg">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-gray-900">
                  Anomalies for {selectedUser.username}
                </h2>
                <p className="text-gray-600 text-sm mt-1">
                  Total anomalies detected: {selectedUser.anomalies_count}
                </p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setSelectedUser(null)}
              >
                Clear Selection
              </Button>
            </div>

            <DataTable data={anomalies} columns={anomalyColumns} hover />
          </Card>
        )}
      </div>
    </div>
  );
};

export default UEBA;
