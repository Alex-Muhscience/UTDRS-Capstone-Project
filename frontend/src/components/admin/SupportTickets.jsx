import { useState } from 'react';
import { FiMessageSquare, FiCheck, FiAlertCircle, FiClock } from 'react-icons/fi';
import Modal from '../shared/Modal';

const statusIcons = {
  open: FiAlertCircle,
  in_progress: FiClock,
  resolved: FiCheck
};

const statusColors = {
  open: 'text-danger',
  in_progress: 'text-warning',
  resolved: 'text-success'
};

export default function SupportTickets() {
  const [tickets, setTickets] = useState([
    {
      id: 1,
      subject: 'Cannot access dashboard',
      client: 'Acme Corp',
      priority: 'high',
      status: 'open',
      createdAt: '2025-04-25T10:30:00Z',
      lastUpdated: '2025-04-25T10:30:00Z'
    },
    {
      id: 2,
      subject: 'License renewal question',
      client: 'Globex Inc',
      priority: 'medium',
      status: 'in_progress',
      createdAt: '2025-04-24T14:15:00Z',
      lastUpdated: '2025-04-25T09:45:00Z'
    },
    {
      id: 3,
      subject: 'Feature request',
      client: 'Initech',
      priority: 'low',
      status: 'resolved',
      createdAt: '2025-04-20T08:00:00Z',
      lastUpdated: '2025-04-22T16:30:00Z'
    }
  ]);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [replyText, setReplyText] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handleStatusChange = (ticketId, newStatus) => {
    setTickets(tickets.map(ticket => 
      ticket.id === ticketId 
        ? { ...ticket, status: newStatus, lastUpdated: new Date().toISOString() } 
        : ticket
    ));
  };

  const handleReplySubmit = (e) => {
    e.preventDefault();
    if (!replyText.trim()) return;
    
    // In a real app, this would send the reply to the backend
    setSelectedTicket({
      ...selectedTicket,
      replies: [...(selectedTicket.replies || []), {
        id: Date.now(),
        text: replyText,
        isAdmin: true,
        createdAt: new Date().toISOString()
      }]
    });
    
    setReplyText('');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Support Tickets</h2>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-dark-light">
            <thead className="bg-dark">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Ticket ID
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Subject
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Client
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Priority
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Last Updated
                </th>
                <th scope="col" className="relative px-6 py-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="bg-dark-light divide-y divide-dark-light">
              {tickets.map((ticket) => {
                const StatusIcon = statusIcons[ticket.status];
                return (
                  <tr key={ticket.id} className="hover:bg-dark">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                      #{ticket.id}
                    </td>
                    <td className="px-6 py-4 text-sm text-white max-w-xs truncate">
                      {ticket.subject}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {ticket.client}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        ticket.priority === 'high' ? 'bg-danger text-white' :
                        ticket.priority === 'medium' ? 'bg-warning text-dark-darker' :
                        'bg-success text-white'
                      }`}>
                        {ticket.priority}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      <div className="flex items-center">
                        <StatusIcon className={`h-4 w-4 mr-1 ${statusColors[ticket.status]}`} />
                        <span className="capitalize">{ticket.status.replace('_', ' ')}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {new Date(ticket.lastUpdated).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button
                        onClick={() => {
                          setSelectedTicket(ticket);
                          setIsModalOpen(true);
                        }}
                        className="text-cyber-blue hover:text-cyber-blue-dark"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        title={`Ticket #${selectedTicket?.id}: ${selectedTicket?.subject}`}
        size="lg"
      >
        {selectedTicket && (
          <div className="space-y-4">
            <div className="bg-dark rounded-lg p-4">
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="text-sm font-medium text-white">Client: {selectedTicket.client}</h4>
                  <p className="text-sm text-gray-400 mt-1">
                    Created: {new Date(selectedTicket.createdAt).toLocaleString()}
                  </p>
                </div>
                <div className="flex space-x-2">
                  <select
                    value={selectedTicket.status}
                    onChange={(e) => {
                      handleStatusChange(selectedTicket.id, e.target.value);
                      setSelectedTicket({...selectedTicket, status: e.target.value});
                    }}
                    className="bg-dark-light border border-dark-light text-white text-sm rounded-md focus:ring-cyber-blue focus:border-cyber-blue block p-1"
                  >
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="space-y-4 max-h-96 overflow-y-auto">
              {(selectedTicket.replies || []).map((reply) => (
                <div
                  key={reply.id}
                  className={`p-3 rounded-lg ${reply.isAdmin ? 'bg-dark-light' : 'bg-dark'}`}
                >
                  <div className="flex justify-between items-start">
                    <span className="text-sm font-medium text-white">
                      {reply.isAdmin ? 'Admin' : selectedTicket.client}
                    </span>
                    <span className="text-xs text-gray-400">
                      {new Date(reply.createdAt).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-gray-300">{reply.text}</p>
                </div>
              ))}
            </div>

            <form onSubmit={handleReplySubmit} className="mt-4">
              <div className="flex items-start space-x-2">
                <div className="flex-1">
                  <textarea
                    rows={3}
                    value={replyText}
                    onChange={(e) => setReplyText(e.target.value)}
                    className="block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
                    placeholder="Type your reply here..."
                  />
                </div>
                <button
                  type="submit"
                  className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
                >
                  <FiMessageSquare className="h-4 w-4" />
                </button>
              </div>
            </form>
          </div>
        )}
      </Modal>
    </div>
  );
}