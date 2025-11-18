import React, { useState, useCallback } from "react";

export interface Column<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  width?: string;
  render?: (value: T[keyof T], row: T) => React.ReactNode;
}

export interface DataTableProps<T extends { id: string | number }> {
  data: T[];
  columns: Column<T>[];
  loading?: boolean;
  pagination?: {
    limit: number;
    offset: number;
    total: number;
    onPaginationChange: (offset: number, limit: number) => void;
  };
  onRowClick?: (row: T) => void;
  onSelectionChange?: (selectedIds: (string | number)[]) => void;
  selectable?: boolean;
  striped?: boolean;
  hover?: boolean;
  compact?: boolean;
  className?: string;
}

const DataTable = React.forwardRef<HTMLDivElement, DataTableProps<any>>(
  (
    {
      data,
      columns,
      loading = false,
      pagination,
      onRowClick,
      onSelectionChange,
      selectable = false,
      striped = true,
      hover = true,
      compact = false,
      className = "",
    },
    ref
  ) => {
    const [sortConfig, setSortConfig] = useState<{
      key: string;
      direction: "asc" | "desc";
    } | null>(null);
    const [selectedIds, setSelectedIds] = useState<Set<string | number>>(
      new Set()
    );

    const handleSort = useCallback((key: string) => {
      setSortConfig((current) => {
        if (current?.key === key) {
          // Toggle direction or reset
          const newDirection = current.direction === "asc" ? "desc" : "asc";
          return { key, direction: newDirection };
        }
        return { key, direction: "asc" };
      });
    }, []);

    const handleSelectAll = useCallback(() => {
      if (selectedIds.size === data.length) {
        setSelectedIds(new Set());
        onSelectionChange?.([]);
      } else {
        const allIds = new Set(data.map((row) => row.id));
        setSelectedIds(allIds);
        onSelectionChange?.(Array.from(allIds));
      }
    }, [data, selectedIds.size, onSelectionChange]);

    const handleSelectRow = useCallback(
      (id: string | number) => {
        const newSelection = new Set(selectedIds);
        if (newSelection.has(id)) {
          newSelection.delete(id);
        } else {
          newSelection.add(id);
        }
        setSelectedIds(newSelection);
        onSelectionChange?.(Array.from(newSelection));
      },
      [selectedIds, onSelectionChange]
    );

    const paddingClass = compact ? "px-3 py-2" : "px-4 py-3";

    return (
      <div
        ref={ref}
        className={`
          overflow-x-auto rounded-lg border border-gray-200
          ${className}
        `}
      >
        <table className="w-full text-sm text-left text-gray-700">
          {/* Header */}
          <thead className="bg-gray-50 border-b border-gray-200 font-semibold">
            <tr>
              {selectable && (
                <th className={`w-10 ${paddingClass}`}>
                  <input
                    type="checkbox"
                    checked={
                      selectedIds.size === data.length && data.length > 0
                    }
                    onChange={handleSelectAll}
                    className="w-4 h-4 rounded cursor-pointer"
                  />
                </th>
              )}
              {columns.map((column) => (
                <th
                  key={String(column.key)}
                  className={`${paddingClass} ${
                    column.sortable ? "cursor-pointer hover:bg-gray-100" : ""
                  }`}
                  style={column.width ? { width: column.width } : {}}
                  onClick={() =>
                    column.sortable && handleSort(String(column.key))
                  }
                >
                  <div className="flex items-center gap-2">
                    <span>{column.label}</span>
                    {column.sortable &&
                      sortConfig?.key === String(column.key) && (
                        <svg
                          className={`w-4 h-4 transition-transform ${
                            sortConfig.direction === "desc" ? "rotate-180" : ""
                          }`}
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M7 16V4m0 0L3 8m0 0l4 4m10 0v12m0 0l4-4m-4 4l-4-4"
                          />
                        </svg>
                      )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>

          {/* Body */}
          <tbody>
            {loading ? (
              <tr>
                <td
                  colSpan={columns.length + (selectable ? 1 : 0)}
                  className="p-8 text-center"
                >
                  <div className="flex items-center justify-center">
                    <svg
                      className="animate-spin h-6 w-6 text-blue-600"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                  </div>
                </td>
              </tr>
            ) : data.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length + (selectable ? 1 : 0)}
                  className="p-8 text-center text-gray-500"
                >
                  No data available
                </td>
              </tr>
            ) : (
              data.map((row, rowIndex) => (
                <tr
                  key={row.id}
                  onClick={() => onRowClick?.(row)}
                  className={`
                    border-b border-gray-200
                    transition-colors
                    ${striped && rowIndex % 2 === 0 ? "bg-gray-50" : ""}
                    ${hover ? "hover:bg-blue-50 cursor-pointer" : ""}
                  `}
                >
                  {selectable && (
                    <td className={`w-10 ${paddingClass}`}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(row.id)}
                        onChange={() => handleSelectRow(row.id)}
                        onClick={(e) => e.stopPropagation()}
                        className="w-4 h-4 rounded cursor-pointer"
                      />
                    </td>
                  )}
                  {columns.map((column) => (
                    <td key={String(column.key)} className={paddingClass}>
                      {column.render
                        ? column.render(row[column.key], row)
                        : String(row[column.key])}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {pagination && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
            <div className="text-sm text-gray-600">
              Showing {pagination.offset + 1} to{" "}
              {Math.min(pagination.offset + pagination.limit, pagination.total)}{" "}
              of {pagination.total} results
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() =>
                  pagination.onPaginationChange(
                    Math.max(0, pagination.offset - pagination.limit),
                    pagination.limit
                  )
                }
                disabled={pagination.offset === 0}
                className="px-3 py-1 rounded border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>

              <span className="text-sm text-gray-600">
                Page {Math.floor(pagination.offset / pagination.limit) + 1}
              </span>

              <button
                onClick={() =>
                  pagination.onPaginationChange(
                    pagination.offset + pagination.limit,
                    pagination.limit
                  )
                }
                disabled={
                  pagination.offset + pagination.limit >= pagination.total
                }
                className="px-3 py-1 rounded border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }
);

DataTable.displayName = "DataTable";

export default DataTable;
