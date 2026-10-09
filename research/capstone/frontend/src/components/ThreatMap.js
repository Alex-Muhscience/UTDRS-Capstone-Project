import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

const ThreatMap = ({ threats }) => {
    const formattedData = threats.map((threat, index) => ({
        name: `Threat ${index + 1}`,
        severity: threat.severity,
    }));

    return (
        <div style={styles.map}>
            <h3>Threat Map</h3>
            <BarChart
                width={600}
                height={300}
                data={formattedData}
                margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
            >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="severity" fill="#8884d8" />
            </BarChart>
        </div>
    );
};

const styles = { map: { padding: '1rem', border: '1px solid #ccc', margin: '2rem auto' } };

export default ThreatMap;
