// BlueteamingAsia - Dashboard Charts

function initDashboardCharts(severityData, dailyCounts) {
    // Severity Doughnut Chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        const labels = ['Info', 'Low', 'Medium', 'High', 'Critical'];
        const keys = ['info', 'low', 'medium', 'high', 'critical'];
        const colors = ['#6b7280', '#3b82f6', '#f59e0b', '#ef4444', '#dc2626'];
        const data = keys.map(function(k) { return severityData[k] || 0; });

        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 15, usePointStyle: true }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // Daily Events Line Chart
    const timelineCtx = document.getElementById('timelineChart');
    if (timelineCtx) {
        const labels = dailyCounts.map(function(d) { return d.date; });
        const data = dailyCounts.map(function(d) { return d.count; });

        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Events',
                    data: data,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointBackgroundColor: '#3b82f6',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 },
                        grid: { color: 'rgba(0,0,0,0.05)' }
                    },
                    x: {
                        grid: { display: false }
                    }
                }
            }
        });
    }
}
