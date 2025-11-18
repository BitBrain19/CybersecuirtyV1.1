import React, { useState, useEffect } from "react";
import Button from "@/components/Button";
import Card from "@/components/Card";
import DataTable from "@/components/DataTable";
import Modal from "@/components/Modal";
import { useToast } from "@/hooks/useToast";

interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger_type: string;
  enabled: boolean;
  last_run?: string;
  success_rate: number;
}

interface PlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_name: string;
  status: "pending" | "running" | "success" | "failed";
  started_at: string;
  completed_at?: string;
  result?: string;
}

const SOAR: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(
    null
  );
  const [showModal, setShowModal] = useState(false);
  const { success, error } = useToast();

  // Fetch playbooks on mount
  useEffect(() => {
    const fetchPlaybooks = async () => {
      try {
        setLoading(true);
        const response = await fetch(
          `${import.meta.env.VITE_API_URL}/soar/playbooks`,
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            },
          }
        );

        if (!response.ok) throw new Error("Failed to fetch playbooks");

        const data = await response.json();
        setPlaybooks(data.playbooks || []);
        success("Playbooks loaded successfully");
      } catch (err) {
        error(err instanceof Error ? err.message : "Failed to load playbooks");
      } finally {
        setLoading(false);
      }
    };

    fetchPlaybooks();
  }, []);

  const handleRunPlaybook = async (playbook: Playbook) => {
    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL}/soar/playbooks/${playbook.id}/run`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({}),
        }
      );

      if (!response.ok) throw new Error("Failed to run playbook");

      const data = await response.json();
      setExecutions([data, ...executions]);
      success(`Playbook "${playbook.name}" executed successfully`);
      setShowModal(false);
    } catch (err) {
      error(err instanceof Error ? err.message : "Failed to run playbook");
    }
  };

  const playbookColumns = [
    { key: "name" as const, label: "Playbook Name", sortable: true },
    { key: "description" as const, label: "Description" },
    { key: "trigger_type" as const, label: "Trigger Type" },
    {
      key: "success_rate" as const,
      label: "Success Rate",
      render: (value: any) => `${value}%`,
    },
  ];

  const executionColumns = [
    { key: "playbook_name" as const, label: "Playbook", sortable: true },
    {
      key: "status" as const,
      label: "Status",
      render: (value: any) => (
        <span
          className={`px-2 py-1 rounded text-sm font-medium ${
            value === "success"
              ? "bg-green-100 text-green-800"
              : value === "failed"
              ? "bg-red-100 text-red-800"
              : value === "running"
              ? "bg-blue-100 text-blue-800"
              : "bg-gray-100 text-gray-800"
          }`}
        >
          {value.charAt(0).toUpperCase() + value.slice(1)}
        </span>
      ),
    },
    { key: "started_at" as const, label: "Started" },
    { key: "completed_at" as const, label: "Completed" },
  ];

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            SOAR Platform
          </h1>
          <p className="text-gray-600">
            Security Orchestration, Automation, and Response
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                Active Playbooks
              </p>
              <p className="text-3xl font-bold text-blue-600 mt-2">
                {playbooks.filter((p) => p.enabled).length}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">
                Executions (24h)
              </p>
              <p className="text-3xl font-bold text-green-600 mt-2">
                {executions.filter((e) => e.status === "success").length}
              </p>
            </div>
          </Card>

          <Card shadow="md" padding="lg">
            <div className="text-center">
              <p className="text-gray-600 text-sm font-medium">Failed (24h)</p>
              <p className="text-3xl font-bold text-red-600 mt-2">
                {executions.filter((e) => e.status === "failed").length}
              </p>
            </div>
          </Card>
        </div>

        {/* Playbooks Section */}
        <Card shadow="md" padding="lg" className="mb-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-gray-900">
              Available Playbooks
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
            data={playbooks}
            columns={playbookColumns}
            loading={loading}
            hover
            onRowClick={(row) => {
              setSelectedPlaybook(row);
              setShowModal(true);
            }}
          />
        </Card>

        {/* Executions History */}
        <Card shadow="md" padding="lg">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">
            Recent Executions
          </h2>
          <DataTable data={executions} columns={executionColumns} hover />
        </Card>

        {/* Modal for Playbook Details */}
        <Modal
          isOpen={showModal}
          onClose={() => {
            setShowModal(false);
            setSelectedPlaybook(null);
          }}
          title={selectedPlaybook?.name}
          size="md"
          actions={
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  setShowModal(false);
                  setSelectedPlaybook(null);
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() =>
                  selectedPlaybook && handleRunPlaybook(selectedPlaybook)
                }
              >
                Run Playbook
              </Button>
            </>
          }
        >
          {selectedPlaybook && (
            <div className="space-y-4">
              <div>
                <p className="text-sm font-medium text-gray-700">Description</p>
                <p className="text-gray-900 mt-1">
                  {selectedPlaybook.description}
                </p>
              </div>

              <div>
                <p className="text-sm font-medium text-gray-700">
                  Trigger Type
                </p>
                <p className="text-gray-900 mt-1">
                  {selectedPlaybook.trigger_type}
                </p>
              </div>

              <div>
                <p className="text-sm font-medium text-gray-700">
                  Success Rate
                </p>
                <div className="mt-1 flex items-center gap-2">
                  <div className="flex-1 bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-green-600 h-2 rounded-full transition-all"
                      style={{ width: `${selectedPlaybook.success_rate}%` }}
                    />
                  </div>
                  <span className="text-gray-900 font-medium">
                    {selectedPlaybook.success_rate}%
                  </span>
                </div>
              </div>

              {selectedPlaybook.last_run && (
                <div>
                  <p className="text-sm font-medium text-gray-700">Last Run</p>
                  <p className="text-gray-900 mt-1">
                    {selectedPlaybook.last_run}
                  </p>
                </div>
              )}
            </div>
          )}
        </Modal>
      </div>
    </div>
  );
};

export default SOAR;
