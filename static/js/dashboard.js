/**
 * WebFootprint – Digital Forensics Dashboard JS
 * Chart.js initializers, table filtering, and UI utilities.
 */

document.addEventListener('DOMContentLoaded', function () {
    // 1. Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.getElementById('sidebar');
    const contentWrapper = document.getElementById('content-wrapper');

    if (sidebarToggle && sidebar && contentWrapper) {
        // Restore state
        const isCollapsed = localStorage.getItem('webfootprint_sidebar_collapsed') === 'true';
        if (isCollapsed) {
            sidebar.classList.add('collapsed');
            contentWrapper.classList.add('expanded');
        }

        sidebarToggle.addEventListener('click', function () {
            sidebar.classList.toggle('collapsed');
            contentWrapper.classList.toggle('expanded');
            const state = sidebar.classList.contains('collapsed');
            localStorage.setItem('webfootprint_sidebar_collapsed', state);
        });
    }

    // 2. Client-side Table Search Filter Helper
    const tableSearchInputs = document.querySelectorAll('.table-search-input');
    tableSearchInputs.forEach(input => {
        const targetTableId = input.getAttribute('data-table-id');
        const targetTable = document.getElementById(targetTableId);
        if (!targetTable) return;

        input.addEventListener('keyup', function () {
            const query = this.value.toLowerCase().trim();
            const rows = targetTable.querySelectorAll('tbody tr');

            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                if (text.includes(query)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    });

    // 3. Copy to Clipboard Utility
    window.copyToClipboard = function (text, btnElement) {
        if (!navigator.clipboard) {
            // Fallback
            const textArea = document.createElement("textarea");
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand("copy");
            document.body.removeChild(textArea);
            showCopyFeedback(btnElement);
            return;
        }
        navigator.clipboard.writeText(text).then(() => {
            showCopyFeedback(btnElement);
        }).catch(err => {
            console.error('Copy failed', err);
        });
    };

    function showCopyFeedback(btnElement) {
        if (!btnElement) return;
        const originalHtml = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="fas fa-check text-success"></i> Copied!';
        setTimeout(() => {
            btnElement.innerHTML = originalHtml;
        }, 1800);
    }
});

/**
 * Chart Initialization Helper Functions
 */
const ForensicsCharts = {
    themeColors: {
        bgCard: '#172033',
        textPrimary: '#E5E7EB',
        textSecondary: '#94A3B8',
        border: '#1E293B',
        primary: '#3B82F6',
        accent: '#06B6D4',
        success: '#22C55E',
        warning: '#F59E0B',
        danger: '#EF4444',
        palette: ['#3B82F6', '#06B6D4', '#22C55E', '#F59E0B', '#A855F7', '#EC4899', '#6366F1', '#14B8A6']
    },

    // Daily Activity Line / Area Chart
    initDailyActivityChart: function (canvasId, dates, counts) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: dates,
                datasets: [{
                    label: 'Website Visits',
                    data: counts,
                    borderColor: this.themeColors.accent,
                    backgroundColor: 'rgba(6, 182, 212, 0.12)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointBackgroundColor: this.themeColors.accent,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#111827',
                        titleColor: '#F8FAFC',
                        bodyColor: '#E5E7EB',
                        borderColor: '#334155',
                        borderWidth: 1,
                        padding: 10
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(30, 41, 59, 0.4)' },
                        ticks: { color: this.themeColors.textSecondary, font: { size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(30, 41, 59, 0.4)' },
                        ticks: { color: this.themeColors.textSecondary, font: { size: 11 } }
                    }
                }
            }
        });
    },

    // Top Domains Horizontal Bar Chart
    initTopDomainsChart: function (canvasId, domains, visits) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: domains,
                datasets: [{
                    label: 'Total Visits',
                    data: visits,
                    backgroundColor: 'rgba(59, 130, 246, 0.75)',
                    borderColor: this.themeColors.primary,
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#111827',
                        borderColor: '#334155',
                        borderWidth: 1,
                        padding: 10
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: 'rgba(30, 41, 59, 0.4)' },
                        ticks: { color: this.themeColors.textSecondary, font: { size: 11 } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: this.themeColors.textSecondary, font: { size: 11 } }
                    }
                }
            }
        });
    },

    // Browser Distribution Doughnut Chart
    initBrowserDistChart: function (canvasId, labels, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#3B82F6', '#06B6D4', '#22C55E', '#F59E0B', '#8B5CF6'
                    ],
                    borderColor: '#172033',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: this.themeColors.textSecondary, boxWidth: 12, font: { size: 11 } }
                    }
                },
                cutout: '65%'
            }
        });
    },

    // Risk Classification Doughnut Chart
    initRiskRatioChart: function (canvasId, labels, counts) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const colors = labels.map(l => {
            const lower = (l || '').toLowerCase();
            if (lower.includes('high')) return '#EF4444';
            if (lower.includes('suspicious') || lower.includes('medium')) return '#F59E0B';
            return '#22C55E';
        });

        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: colors,
                    borderColor: '#172033',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: this.themeColors.textSecondary, boxWidth: 12, font: { size: 11 } }
                    }
                },
                cutout: '65%'
            }
        });
    },

    // Hourly Activity Bar Chart
    initHourlyActivityChart: function (canvasId, hours, counts) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: hours.map(h => `${h}:00`),
                datasets: [{
                    label: 'Visits per Hour',
                    data: counts,
                    backgroundColor: 'rgba(6, 182, 212, 0.65)',
                    borderColor: this.themeColors.accent,
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: this.themeColors.textSecondary, font: { size: 10 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(30, 41, 59, 0.4)' },
                        ticks: { color: this.themeColors.textSecondary, font: { size: 10 } }
                    }
                }
            }
        });
    }
};
