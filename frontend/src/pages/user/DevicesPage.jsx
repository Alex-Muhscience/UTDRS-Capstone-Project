import DeviceManagement from '../../components/user/DeviceManagement';
import Navbar from '../../components/shared/Navbar';
import Sidebar from '../../components/shared/Sidebar';

export default function DevicesPage() {
  return (
    <div className="h-screen bg-dark-darker overflow-hidden flex">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Navbar />
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-dark-darker">
          <div className="max-w-7xl mx-auto">
            <DeviceManagement />
          </div>
        </main>
      </div>
    </div>
  );
}