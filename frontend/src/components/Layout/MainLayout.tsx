import React from "react";
import TopNav, { type TopNavProps } from "./TopNav";
import Sidebar, { type NavItem } from "./Sidebar";

interface MainLayoutProps {
  children: React.ReactNode;
  sidebarItems?: NavItem[];
  topNavProps?: Partial<TopNavProps>;
  sidebarCollapsed?: boolean;
  onSidebarToggle?: () => void;
  className?: string;
}

const MainLayout = React.forwardRef<HTMLDivElement, MainLayoutProps>(
  (
    {
      children,
      sidebarItems = [],
      topNavProps = {},
      sidebarCollapsed = false,
      onSidebarToggle,
      className = "",
    },
    ref
  ) => {
    return (
      <div ref={ref} className="flex h-screen bg-gray-50">
        {/* Sidebar */}
        {sidebarItems.length > 0 && (
          <Sidebar
            items={sidebarItems}
            collapsed={sidebarCollapsed}
            onToggleCollapse={onSidebarToggle}
            logo="🔒"
          />
        )}

        {/* Main Content */}
        <div className="flex flex-col flex-1 overflow-hidden">
          {/* Top Navigation */}
          <TopNav {...topNavProps} />

          {/* Page Content */}
          <main
            className={`
              flex-1 overflow-y-auto
              ${className}
            `}
          >
            <div className="h-full w-full">{children}</div>
          </main>
        </div>
      </div>
    );
  }
);

MainLayout.displayName = "MainLayout";

export default MainLayout;
