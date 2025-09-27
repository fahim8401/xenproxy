window.addEventListener("DOMContentLoaded", function() {
  // Example Chart.js integration for resource graphs
  function makeChart(ctx, label, data, color) {
    return new Chart(ctx, {
      type: "line",
      data: {
        labels: Array(data.length).fill(""),
        datasets: [{
          label: label,
          data: data,
          borderColor: color,
          backgroundColor: "rgba(0,0,0,0.05)",
          fill: true,
          tension: 0.2
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { x: { display: false } }
      }
    });
  }

  // Dummy data for demonstration
  let cpuData = [10, 20, 15, 30, 25, 40, 35, 30, 20, 10];
  let memData = [100, 120, 110, 130, 125, 140, 135, 130, 120, 110];
  let bwData = [5, 10, 7, 12, 9, 15, 13, 10, 8, 6];

  if (document.getElementById("cpuChart")) {
    makeChart(document.getElementById("cpuChart"), "CPU %", cpuData, "#2563eb");
  }
  if (document.getElementById("memChart")) {
    makeChart(document.getElementById("memChart"), "Memory MB", memData, "#f59e42");
  }
  if (document.getElementById("bwChart")) {
    makeChart(document.getElementById("bwChart"), "Bandwidth KB/s", bwData, "#22c55e");
  }
});
