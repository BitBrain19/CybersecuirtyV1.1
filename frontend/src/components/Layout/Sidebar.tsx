import React from "react";

export interface NavItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  href?: string;
  onClick?: () => void;
  active?: boolean;
  badge?: string | number;
  children?: NavItem[];
  expanded?: boolean;
}

interface SidebarProps {
  items: NavItem[];
  onItemClick?: (item: NavItem) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  width?: string;
  logo?: React.ReactNode;
}

const Sidebar = React.forwardRef<HTMLDivElement, SidebarProps>(
  (
    {
      items,
      onItemClick,
      collapsed = false,
      onToggleCollapse,
      width = "w-64",
      logo,
    },
    ref
  ) => {
    const [expandedItems, setExpandedItems] = React.useState<Set<string>>(
      new Set()
    );

    const toggleExpandItem = (id: string) => {
      const newExpanded = new Set(expandedItems);
      if (newExpanded.has(id)) {
        newExpanded.delete(id);
      } else {
        newExpanded.add(id);
      }
      setExpandedItems(newExpanded);
    };

    const handleItemClick = (item: NavItem) => {
      if (item.children) {
        toggleExpandItem(item.id);
      }
      item.onClick?.();
      onItemClick?.(item);
    };

    const renderNavItem = (item: NavItem, level = 0) => {
      const isExpanded = expandedItems.has(item.id);
      const hasChildren = item.children && item.children.length > 0;

      return (
        <div key={item.id}>
          <button
            onClick={() => handleItemClick(item)}
            className={`
              w-full flex items-center gap-3 px-4 py-2 text-sm font-medium
              transition-colors duration-200
              ${
                item.active
                  ? "bg-blue-50 text-blue-600 border-r-4 border-blue-600"
                  : "text-gray-700 hover:bg-gray-50 hover:text-gray-900"
              }
              ${level > 0 ? "ml-4 border-r-0" : ""}
            `}
            style={{ paddingLeft: `${16 + level * 16}px` }}
          >
            {item.icon && (
              <span className="flex-shrink-0 w-5 h-5">{item.icon}</span>
            )}
            {!collapsed && (
              <>
                <span className="flex-1 text-left">{item.label}</span>
                {hasChildren && (
                  <svg
                    className={`w-4 h-4 transition-transform duration-200 ${
                      isExpanded ? "transform rotate-180" : ""
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 14l-7 7m0 0l-7-7m7 7V3"
                    />
                  </svg>
                )}
                {item.badge && (
                  <span className="inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-white bg-red-600 rounded-full">
                    {item.badge}
                  </span>
                )}
              </>
            )}
          </button>

          {/* Children */}
          {hasChildren && isExpanded && !collapsed && (
            <div className="space-y-1">
              {item.children?.map((child) => renderNavItem(child, level + 1))}
            </div>
          )}
        </div>
      );
    };

    return (
      <div
        ref={ref}
        className={`
          bg-white border-r border-gray-200 flex flex-col h-screen sticky top-0
          transition-all duration-300
          ${collapsed ? "w-20" : width}
        `}
      >
        {/* Logo Area */}
        <div className="flex items-center justify-between px-4 py-4 border-b border-gray-200 h-16">
          {!collapsed && logo && (
            <div className="text-xl font-bold text-blue-600">{logo}</div>
          )}
          <button
            onClick={onToggleCollapse}
            className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
            title="Toggle sidebar"
          >
            <svg
              className="w-5 h-5 text-gray-600"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 6h16M4 12h16M4 18h16"
              />
            </svg>
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 overflow-y-auto space-y-1 px-2 py-4">
          {items.map((item) => renderNavItem(item))}
        </nav>

        {/* Footer */}
        <div className="border-t border-gray-200 px-4 py-4">
          {!collapsed && (
            <div className="text-xs text-gray-500">
              <p className="font-semibold mb-1">SecurityAI</p>
              <p>v1.0 | © 2025</p>
            </div>
          )}
        </div>
      </div>
    );
  }
);

Sidebar.displayName = "Sidebar";

export default Sidebar;
