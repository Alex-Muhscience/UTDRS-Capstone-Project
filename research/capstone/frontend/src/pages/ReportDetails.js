import React from 'react';
import { useParams } from 'react-router-dom';

const ReportDetails = () => {
  const { reportId } = useParams();

  return (
    <div>
      <h1>Report Details</h1>
      <p>Displaying details for Report ID: {reportId}</p>
    </div>
  );
};

export default ReportDetails;
