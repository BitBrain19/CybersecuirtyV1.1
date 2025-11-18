import { useState, useCallback } from "react";
import { Toast } from "@/components/Toast";

export const useToast = () => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback(
    (
      message: string,
      type: "success" | "error" | "warning" | "info" = "info",
      duration = 5000,
      action?: { label: string; onClick: () => void }
    ) => {
      const id = `toast-${Date.now()}-${Math.random()}`;
      const newToast: Toast = {
        id,
        message,
        type,
        duration,
        action,
      };

      setToasts((prev) => [...prev, newToast]);
      return id;
    },
    []
  );

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const success = useCallback(
    (
      message: string,
      duration?: number,
      action?: { label: string; onClick: () => void }
    ) => addToast(message, "success", duration, action),
    [addToast]
  );

  const error = useCallback(
    (
      message: string,
      duration?: number,
      action?: { label: string; onClick: () => void }
    ) => addToast(message, "error", duration, action),
    [addToast]
  );

  const warning = useCallback(
    (
      message: string,
      duration?: number,
      action?: { label: string; onClick: () => void }
    ) => addToast(message, "warning", duration, action),
    [addToast]
  );

  const info = useCallback(
    (
      message: string,
      duration?: number,
      action?: { label: string; onClick: () => void }
    ) => addToast(message, "info", duration, action),
    [addToast]
  );

  return {
    toasts,
    addToast,
    removeToast,
    success,
    error,
    warning,
    info,
  };
};
