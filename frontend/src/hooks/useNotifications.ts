import { useEffect, useState, useCallback } from "react";

export interface Notification {
  id: string;
  user_id: string;
  title: string;
  message: string;
  type: "threat" | "vulnerability" | "alert" | "system" | "info";
  severity: "critical" | "high" | "medium" | "low" | "info";
  read: boolean;
  resource_id?: string;
  resource_type?: string;
  action_url?: string;
  created_at: string;
  updated_at: string;
}

export const useNotifications = (enabled = true) => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const apiUrl = import.meta.env.VITE_API_URL;
  const token = localStorage.getItem("accessToken");

  // Fetch notifications
  const fetchNotifications = useCallback(
    async (limit = 20, offset = 0) => {
      if (!token) {
        setError("Not authenticated");
        return;
      }

      setLoading(true);
      try {
        const response = await fetch(
          `${apiUrl}/api/v1/notifications?limit=${limit}&offset=${offset}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (!response.ok) {
          throw new Error("Failed to fetch notifications");
        }

        const data = await response.json();
        setNotifications(data.notifications || []);
        setUnreadCount(data.unread_count || 0);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
      } finally {
        setLoading(false);
      }
    },
    [token, apiUrl]
  );

  // Mark notification as read
  const markAsRead = useCallback(
    async (notificationId: string) => {
      if (!token) return;

      try {
        const response = await fetch(
          `${apiUrl}/api/v1/notifications/${notificationId}/read`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (response.ok) {
          setNotifications((prev) =>
            prev.map((n) =>
              n.id === notificationId ? { ...n, read: true } : n
            )
          );
          setUnreadCount((prev) => Math.max(0, prev - 1));
        }
      } catch (err) {
        console.error("Failed to mark notification as read:", err);
      }
    },
    [token, apiUrl]
  );

  // Mark notification as unread
  const markAsUnread = useCallback(
    async (notificationId: string) => {
      if (!token) return;

      try {
        const response = await fetch(
          `${apiUrl}/api/v1/notifications/${notificationId}/unread`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (response.ok) {
          setNotifications((prev) =>
            prev.map((n) =>
              n.id === notificationId ? { ...n, read: false } : n
            )
          );
          setUnreadCount((prev) => prev + 1);
        }
      } catch (err) {
        console.error("Failed to mark notification as unread:", err);
      }
    },
    [token, apiUrl]
  );

  // Delete notification
  const deleteNotification = useCallback(
    async (notificationId: string) => {
      if (!token) return;

      try {
        const response = await fetch(
          `${apiUrl}/api/v1/notifications/${notificationId}`,
          {
            method: "DELETE",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (response.ok) {
          setNotifications((prev) =>
            prev.filter((n) => n.id !== notificationId)
          );
        }
      } catch (err) {
        console.error("Failed to delete notification:", err);
      }
    },
    [token, apiUrl]
  );

  // Mark all as read
  const markAllAsRead = useCallback(async () => {
    if (!token) return;

    try {
      const response = await fetch(
        `${apiUrl}/api/v1/notifications/mark-all-read`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (response.ok) {
        setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
        setUnreadCount(0);
      }
    } catch (err) {
      console.error("Failed to mark all as read:", err);
    }
  }, [token, apiUrl]);

  // Fetch on mount if enabled
  useEffect(() => {
    if (enabled && token) {
      fetchNotifications();
      // Poll every 30 seconds
      const interval = setInterval(fetchNotifications, 30000);
      return () => clearInterval(interval);
    }
  }, [enabled, token, fetchNotifications]);

  return {
    notifications,
    unreadCount,
    loading,
    error,
    fetchNotifications,
    markAsRead,
    markAsUnread,
    deleteNotification,
    markAllAsRead,
  };
};
