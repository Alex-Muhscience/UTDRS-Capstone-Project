export const isAdmin = (user) => user?.role === 'admin';
export const isAnalyst = (user) => user?.role === 'analyst';
export const isViewer = (user) => user?.role === 'viewer';
