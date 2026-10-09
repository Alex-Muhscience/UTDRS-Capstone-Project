export const formatDate = (dateString) => {
    const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    return new Date(dateString).toLocaleDateString(undefined, options);
  };
  
  export const severityColors = {
    critical: 'bg-danger text-white',
    high: 'bg-warning text-dark-darker',
    medium: 'bg-info text-white',
    low: 'bg-success text-white'
  };
  
  export const statusColors = {
    online: 'text-success',
    offline: 'text-gray-500',
    compromised: 'text-danger',
    at_risk: 'text-warning'
  };
  
  export const truncateString = (str, num = 50) => {
    if (str.length <= num) {
      return str;
    }
    return str.slice(0, num) + '...';
  };
  
  export const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };