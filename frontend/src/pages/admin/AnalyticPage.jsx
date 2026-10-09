import Analytics from '../../components/admin/Analytics';
import Navbar from '../../components/shared/Navbar';
import Sidebar from '../../components/shared/Sidebar';

export default function AnalyticsPage() {
  return (
    <div className="h-screen bg-dark-darker overflow-hidden flex">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Navbar />
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-dark-darker">
          <div className="max-w-7xl mx-auto">
            <Analytics />
          </div>
        </main>
      </div>
    </div>
  );
}