import React from 'react';
import { useDataContext } from '../context/DataContext';
import ReportsList from '../../components/user/ReportsList';

const ReportsPage = () => {
  const { userReports } = useDataContext();

  return (
    <div className="reports-page">
      <h1>Your Security Reports</h1>
      <ReportsList reports={userReports} />
    </div>
  );
};

export default ReportsPage;