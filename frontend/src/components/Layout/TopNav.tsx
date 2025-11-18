import React from "react";

interface TopNavProps {
  logo?: React.ReactNode;
  title?: string;
  searchEnabled?: boolean;
  onSearch?: (query: string) => void;
  rightContent?: React.ReactNode;
  onNotificationClick?: () => void;
  notificationCount?: number;
  onUserMenuClick?: () => void;
  userName?: string;
  userAvatar?: string;
}

const TopNav = React.forwardRef<HTMLDivElement, TopNavProps>(
  (
    {
      logo,
      title = "SecurityAI",
      searchEnabled = true,
      onSearch,
      rightContent,
      onNotificationClick,
      notificationCount = 0,
      onUserMenuClick,
      userName = "User",
      userAvatar,
    },
    ref
  ) => {
    const [searchQuery, setSearchQuery] = React.useState("");

    const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const query = e.target.value;
      setSearchQuery(query);
      onSearch?.(query);
    };

    return (
      <div
        ref={ref}
        className="bg-white border-b border-gray-200 shadow-sm sticky top-0 z-50"
      >
        <div className="flex items-center justify-between px-6 py-4 h-16">
          {/* Left: Logo & Title */}
          <div className="flex items-center gap-4">
            {logo ? (
              <div className="text-2xl font-bold text-blue-600">{logo}</div>
            ) : (
              <div className="text-2xl font-bold text-blue-600">🔒</div>
            )}
            <h1 className="text-xl font-semibold text-gray-900">{title}</h1>
          </div>

          {/* Center: Search Bar */}
          {searchEnabled && (
            <div className="flex-1 max-w-md mx-8">
              <div className="relative">
                <svg
                  className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                  />
                </svg>
                <input
                  type="text"
                  placeholder="Search threats, endpoints, users..."
                  value={searchQuery}
                  onChange={handleSearchChange}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                />
              </div>
            </div>
          )}

          {/* Right: Actions */}
          <div className="flex items-center gap-6">
            {/* Notification Bell */}
            <button
              onClick={onNotificationClick}
              className="relative p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
              title="Notifications"
            >
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
                />
              </svg>
              {notificationCount > 0 && (
                <span className="absolute top-1 right-1 inline-flex items-center justify-center px-2 py-1 text-xs font-bold leading-none text-white transform translate-x-1/2 -translate-y-1/2 bg-red-600 rounded-full w-5 h-5">
                  {notificationCount > 9 ? "9+" : notificationCount}
                </span>
              )}
            </button>

            {/* User Menu */}
            <button
              onClick={onUserMenuClick}
              className="flex items-center gap-3 p-2 rounded-lg hover:bg-gray-100 transition-colors"
              title="User menu"
            >
              {userAvatar ? (
                <img
                  src={userAvatar}
                  alt={userName}
                  className="w-8 h-8 rounded-full"
                />
              ) : (
                <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm font-medium">
                  {userName.charAt(0).toUpperCase()}
                </div>
              )}
              <span className="text-sm font-medium text-gray-700 hidden sm:inline">
                {userName}
              </span>
              <svg
                className="w-4 h-4 text-gray-400"
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
            </button>

            {/* Custom Right Content */}
            {rightContent && (
              <div className="flex items-center gap-4">{rightContent}</div>
            )}
          </div>
        </div>
      </div>
    );
  }
);

TopNav.displayName = "TopNav";

export default TopNav;
export type { TopNavProps };
