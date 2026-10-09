import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DeviceManagement from '../user/DeviceManagement';
import * as api from '../../api/userApi';
import { toast } from 'react-toastify';

// Mock API
jest.mock('../../api/userApi');
jest.mock('react-toastify');

const mockDevices = [
  {
    _id: '1',
    name: 'Server 1',
    ip: '192.168.1.1',
    status: 'online',
    mac: '00:11:22:33:44:55',
    os: 'Ubuntu 20.04',
    lastSeen: '2024-03-12T10:00:00Z',
    vulnerabilitiesCount: 2,
    threatsCount: 0,
  },
  {
    _id: '2',
    name: 'Server 2',
    ip: '192.168.1.2',
    status: 'offline',
    mac: '00:11:22:33:44:66',
    os: 'Windows Server 2019',
    lastSeen: '2024-03-11T15:00:00Z',
    vulnerabilitiesCount: 5,
    threatsCount: 1,
  },
];

describe('DeviceManagement Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    api.getDevices.mockResolvedValue({ data: mockDevices });
  });

  test('renders device management component', async () => {
    render(<DeviceManagement />);
    
    await waitFor(() => {
      expect(screen.getByText('Device Management')).toBeInTheDocument();
    });
  });

  test('fetches and displays devices', async () => {
    render(<DeviceManagement />);
    
    await waitFor(() => {
      expect(screen.getByText('Server 1')).toBeInTheDocument();
      expect(screen.getByText('Server 2')).toBeInTheDocument();
    });
  });

  test('displays device status correctly', async () => {
    render(<DeviceManagement />);
    
    await waitFor(() => {
      expect(screen.getByText('online')).toBeInTheDocument();
      expect(screen.getByText('offline')).toBeInTheDocument();
    });
  });

  test('handles device refresh', async () => {
    render(<DeviceManagement />);
    
    const refreshButton = await screen.findByText('Refresh');
    fireEvent.click(refreshButton);
    
    await waitFor(() => {
      expect(api.getDevices).toHaveBeenCalledTimes(2); // Initial + refresh
      expect(toast.success).toHaveBeenCalledWith('Devices refreshed');
    });
  });

  test('handles device scan', async () => {
    api.scanDevice.mockResolvedValue({ data: {} });
    
    render(<DeviceManagement />);
    
    await waitFor(() => {
      const scanButtons = screen.getAllByText('Scan');
      fireEvent.click(scanButtons[0]);
    });
    
    await waitFor(() => {
      expect(api.scanDevice).toHaveBeenCalledWith('1');
      expect(toast.success).toHaveBeenCalledWith('Scan initiated successfully');
    });
  });

  test('handles device isolation with confirmation', async () => {
    api.isolateDevice.mockResolvedValue({ data: {} });
    window.confirm = jest.fn(() => true);
    
    render(<DeviceManagement />);
    
    await waitFor(() => {
      const isolateButtons = screen.getAllByText('Isolate');
      fireEvent.click(isolateButtons[0]);
    });
    
    await waitFor(() => {
      expect(window.confirm).toHaveBeenCalled();
      expect(api.isolateDevice).toHaveBeenCalledWith('1');
      expect(toast.success).toHaveBeenCalledWith('Device isolation initiated');
    });
  });

  test('shows device details when clicked', async () => {
    render(<DeviceManagement />);
    
    await waitFor(() => {
      const deviceCards = screen.getAllByText('Server 1');
      fireEvent.click(deviceCards[0].closest('div'));
    });
    
    await waitFor(() => {
      expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
      expect(screen.getByText('Ubuntu 20.04')).toBeInTheDocument();
    });
  });

  test('handles API errors gracefully', async () => {
    api.getDevices.mockRejectedValue(new Error('API Error'));
    
    render(<DeviceManagement />);
    
    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Failed to fetch devices');
    });
  });

  test('disables isolate button for offline devices', async () => {
    render(<DeviceManagement />);
    
    await waitFor(() => {
      const isolateButtons = screen.getAllByText('Isolate');
      // Second device is offline, so its isolate button should be disabled
      expect(isolateButtons[1]).toBeDisabled();
    });
  });
});
