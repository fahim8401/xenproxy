document.addEventListener("DOMContentLoaded", function() {
  // Bulk select
  const selectAll = document.getElementById("select-all");
  if (selectAll) {
    selectAll.addEventListener("change", function() {
      document.querySelectorAll('input[name="selected"]').forEach(cb => {
        cb.checked = selectAll.checked;
      });
    });
  }

  // AJAX polling for dashboard stats
  function refreshHostStats() {
    fetch("/api/host_stats")
      .then(r => r.json())
      .then(stats => {
        for (const k in stats) {
          const el = document.getElementById("host-" + k);
          if (el) el.textContent = stats[k];
        }
      });
  }
  setInterval(refreshHostStats, 30000);

  // Toast notifications
  window.showToast = function(msg, type="success") {
    let toast = document.createElement("div");
    toast.className = "toast " + type;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  };

  // Confirm destructive actions
  document.querySelectorAll("form[onsubmit]").forEach(form => {
    form.addEventListener("submit", function(e) {
      if (!confirm(form.getAttribute("onsubmit").replace("return ", "").replace(";", ""))) {
        e.preventDefault();
      }
    });
  });

  // Create container modal (stub)
  const createBtn = document.getElementById("create-container-btn");
  if (createBtn) {
    createBtn.addEventListener("click", function() {
      showToast("Container creation modal not implemented in this stub.", "info");
    });
  }
});
