import { NavLink } from "react-router-dom";
import {
  HomeIcon,
  BellAlertIcon,
  ChartBarIcon,
  DocumentTextIcon,
  Cog6ToothIcon,
  XMarkIcon,
  SparklesIcon,
  UserGroupIcon,
  ComputerDesktopIcon,
} from "@heroicons/react/24/outline";
import ShieldLogo from "@/assets/shield-logo.svg";

type SidebarProps = {
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
};

const navigation = [
  { name: "Dashboard", href: "/", icon: HomeIcon },
  { name: "Alerts", href: "/alerts", icon: BellAlertIcon },
  { name: "Attack Paths", href: "/attack-paths", icon: ChartBarIcon },
  { name: "SOAR", href: "/soar", icon: SparklesIcon },
  { name: "UEBA", href: "/ueba", icon: UserGroupIcon },
  { name: "EDR", href: "/edr", icon: ComputerDesktopIcon },
  { name: "Reports", href: "/reports", icon: DocumentTextIcon },
  { name: "Settings", href: "/settings", icon: Cog6ToothIcon },
];

const Sidebar = ({ sidebarOpen, setSidebarOpen }: SidebarProps) => {
  return (
    <>
      {/* Mobile sidebar */}
      <div
        className={`fixed inset-0 z-40 flex md:hidden ${
          sidebarOpen ? "" : "pointer-events-none"
        }`}
      >
        {/* Overlay */}
        <div
          className={`fixed inset-0 bg-gray-600 ${
            sidebarOpen ? "opacity-75" : "opacity-0 pointer-events-none"
          } transition-opacity ease-linear duration-300`}
          onClick={() => setSidebarOpen(false)}
        />

        {/* Sidebar */}
        <div
          className={`relative flex-1 flex flex-col max-w-xs w-full bg-white/70 dark:bg-gray-800/50 backdrop-blur transform ${
            sidebarOpen ? "translate-x-0" : "-translate-x-full"
          } transition ease-in-out duration-300`}
        >
          <div className="absolute top-0 right-0 -mr-12 pt-2">
            <button
              className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
              onClick={() => setSidebarOpen(false)}
            >
              <span className="sr-only">Close sidebar</span>
              <XMarkIcon className="h-6 w-6 text-white" aria-hidden="true" />
            </button>
          </div>

          <div className="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
            <div className="flex-shrink-0 flex items-center px-4">
              <img className="h-8 w-8" src={ShieldLogo} alt="SecurityAI" />
              <div className="ml-2">
                <span className="block text-lg font-semibold tracking-tight text-gray-900 dark:text-white">
                  SecurityAI
                </span>
                <span className="block text-xs text-gray-500 dark:text-gray-400">
                  Adaptive Cyber Defense
                </span>
              </div>
            </div>
            <nav className="mt-5 px-2 space-y-1">
              {navigation.map((item) => (
                <NavLink
                  key={item.name}
                  to={item.href}
                  className={({ isActive }) =>
                    `group flex items-center px-2 py-2 text-base font-medium rounded-md ${
                      isActive
                        ? "bg-primary-100 text-primary-900 dark:bg-primary-900 dark:text-primary-100"
                        : "text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white"
                    }`
                  }
                >
                  <item.icon
                    className="mr-4 flex-shrink-0 h-6 w-6 text-gray-500 dark:text-gray-400"
                    aria-hidden="true"
                  />
                  {item.name}
                </NavLink>
              ))}
            </nav>
          </div>
        </div>
      </div>

      {/* Desktop sidebar */}
      <div className="hidden md:flex md:flex-shrink-0">
        <div className="flex flex-col w-64">
          <div className="flex flex-col h-0 flex-1 bg-white/60 dark:bg-gray-800/40 backdrop-blur border-r border-gray-200/70 dark:border-gray-700/60">
            <div className="flex-1 flex flex-col pt-5 pb-4 overflow-y-auto">
              <div className="flex items-center flex-shrink-0 px-4">
                <img className="h-8 w-8" src={ShieldLogo} alt="SecurityAI" />
                <div className="ml-2">
                  <span className="block text-lg font-semibold tracking-tight text-gray-900 dark:text-white">
                    SecurityAI
                  </span>
                  <span className="block text-xs text-gray-500 dark:text-gray-400">
                    Adaptive Cyber Defense
                  </span>
                </div>
              </div>
              <nav className="mt-5 flex-1 px-2 space-y-1">
                {navigation.map((item) => (
                  <NavLink
                    key={item.name}
                    to={item.href}
                    className={({ isActive }) =>
                      `group flex items-center px-3 py-2 text-sm font-medium rounded-md ${
                        isActive
                          ? "bg-primary-100/70 text-primary-900 dark:bg-primary-900/40 dark:text-primary-100"
                          : "text-gray-600 hover:bg-gray-100/60 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700/60 dark:hover:text-white"
                      }`
                    }
                  >
                    <item.icon
                      className="mr-3 flex-shrink-0 h-6 w-6 text-gray-500 dark:text-gray-400"
                      aria-hidden="true"
                    />
                    {item.name}
                  </NavLink>
                ))}
              </nav>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
