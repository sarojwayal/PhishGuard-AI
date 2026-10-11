// ===== PhishGuard AI : dashboard charts (needs Chart.js from the CDN) =====
document.addEventListener("DOMContentLoaded", function () {
  var fallback = document.getElementById("chartFallback");

  if (typeof Chart === "undefined") {          // no internet connection
    if (fallback) fallback.hidden = false;
    return;
  }

  Chart.defaults.color = "#93a1c8";
  Chart.defaults.borderColor = "#243256";

  var catCanvas = document.getElementById("catChart");
  var scoreCanvas = document.getElementById("scoreChart");

  if (catCanvas) {
    new Chart(catCanvas, {
      type: "doughnut",
      data: {
        labels: ["Low", "Medium", "High"],
        datasets: [{
          data: JSON.parse(catCanvas.dataset.values),
          backgroundColor: ["#34d399", "#fbbf24", "#f87171"],
          borderWidth: 0
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, cutout: "62%" }
    });
  }

  if (scoreCanvas) {
    new Chart(scoreCanvas, {
      type: "bar",
      data: {
        labels: JSON.parse(scoreCanvas.dataset.labels),
        datasets: [{
          label: "Risk score",
          data: JSON.parse(scoreCanvas.dataset.values),
          backgroundColor: "#6d8cf5",
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { min: 0, max: 100 } },
        plugins: { legend: { display: false } }
      }
    });
  }
});