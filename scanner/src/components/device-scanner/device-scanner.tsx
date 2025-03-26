import React from 'react';

import styles from './device-scanner.css';

export interface device-scannerProps {
  prop?: string;
}

export function device-scanner({prop = 'default value'}: device-scannerProps) {
  return <div className={styles.device-scanner}>device-scanner {prop}</div>;
}
