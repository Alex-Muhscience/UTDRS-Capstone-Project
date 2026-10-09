export const THREAT_TYPES = [
    { id: 'malware', name: 'Malware' },
    { id: 'phishing', name: 'Phishing' },
    { id: 'ddos', name: 'DDoS' },
    { id: 'bruteforce', name: 'Brute Force' },
    { id: 'insider', name: 'Insider Threat' },
    { id: 'misconfig', name: 'Misconfiguration' },
    { id: 'vulnerability', name: 'Vulnerability Exploit' }
  ];
  
  export const LICENSE_TIERS = {
    basic: {
      name: 'Basic',
      features: [
        'Up to 50 devices',
        'Signature-based detection',
        'Weekly reports',
        'Email support'
      ],
      color: 'bg-cyber-blue'
    },
    pro: {
      name: 'Professional',
      features: [
        'Up to 200 devices',
        'Heuristic & anomaly detection',
        'Daily reports',
        'Vulnerability scanning',
        'Priority support'
      ],
      color: 'bg-cyber-teal'
    },
    enterprise: {
      name: 'Enterprise',
      features: [
        'Unlimited devices',
        'All Pro features',
        'Custom playbooks',
        'API access',
        '24/7 support',
        'Dedicated account manager'
      ],
      color: 'bg-cyber-purple'
    }
  };
  
  export const REPORT_TYPES = [
    { id: 'threats', name: 'Threat Summary' },
    { id: 'vulnerabilities', name: 'Vulnerability Report' },
    { id: 'devices', name: 'Device Status' },
    { id: 'compliance', name: 'Compliance Report' }
  ];