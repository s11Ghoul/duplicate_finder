// --- Scan Form ---
document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("scan-form");
  if (form) {
    initScanForm();
  }
});

function initScanForm() {
  const form = document.getElementById("scan-form");
  const searchInput = document.getElementById("country-search");
  const countryItems = document.querySelectorAll(".country-item");
  const selectedDiv = document.getElementById("selected-countries");
  const errorDiv = document.getElementById("form-error");
  const submitBtn = document.getElementById("submit-btn");

  // Filter countries
  searchInput.addEventListener("input", function () {
    const query = this.value.toLowerCase();
    countryItems.forEach(function (item) {
      const text = item.textContent.toLowerCase();
      if (text.includes(query)) {
        item.classList.remove("hidden");
      } else {
        item.classList.add("hidden");
      }
    });
  });

  // Update selected tags
  function updateSelectedTags() {
    const checked = form.querySelectorAll('input[name="countries"]:checked');
    selectedDiv.innerHTML = "";
    checked.forEach(function (cb) {
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.innerHTML =
        cb.value +
        ' <span class="remove" data-code="' +
        cb.value +
        '">&times;</span>';
      selectedDiv.appendChild(tag);
    });

    // Remove handler
    selectedDiv.querySelectorAll(".remove").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const code = this.dataset.code;
        const cb = form.querySelector(
          'input[name="countries"][value="' + code + '"]'
        );
        if (cb) cb.checked = false;
        updateSelectedTags();
      });
    });
  }

  countryItems.forEach(function (item) {
    item.querySelector("input").addEventListener("change", updateSelectedTags);
  });

  // Submit
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    errorDiv.style.display = "none";

    const brands = document.getElementById("brands").value.trim();
    const checked = form.querySelectorAll('input[name="countries"]:checked');
    const countries = Array.from(checked).map(function (cb) {
      return cb.value;
    });

    if (!brands) {
      errorDiv.textContent = "Enter at least one brand";
      errorDiv.style.display = "block";
      return;
    }
    if (countries.length === 0) {
      errorDiv.textContent = "Select at least one country";
      errorDiv.style.display = "block";
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Creating...";

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ brands: brands, countries: countries }),
    })
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        if (data.error) {
          errorDiv.textContent = data.error;
          errorDiv.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.textContent = "Start Scan";
        } else {
          window.location.href = "/jobs/" + data.job_id;
        }
      })
      .catch(function (err) {
        errorDiv.textContent = "Request failed: " + err;
        errorDiv.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.textContent = "Start Scan";
      });
  });
}

// --- SSE for Job Progress ---
function startSSE(jobId) {
  var logArea = document.getElementById("log-area");
  var progressBar = document.getElementById("progress-bar");
  var statusBadge = document.getElementById("job-status");
  var captchaAlert = document.getElementById("captcha-alert");
  var resultsCard = document.getElementById("results-card");
  var resultsList = document.getElementById("results-list");

  var source = new EventSource("/api/jobs/" + jobId + "/stream");

  source.onmessage = function (event) {
    var data = JSON.parse(event.data);

    if (data.type === "log") {
      var line = document.createElement("div");
      line.className = "log-line";
      line.textContent = data.message;
      logArea.appendChild(line);
      logArea.scrollTop = logArea.scrollHeight;
    }

    if (data.type === "progress") {
      // Update progress bar
      var p = data.data;
      if (p.queries_total > 0) {
        var pct = Math.round((p.queries_done / p.queries_total) * 100);
        progressBar.style.width = pct + "%";
      }

      // Update stats
      document.getElementById("stat-brand").textContent =
        "Brand: " + (p.current_brand || "-");
      document.getElementById("stat-country").textContent =
        "Country: " + (p.current_country || "-");
      document.getElementById("stat-query").textContent =
        "Query: " + (p.current_query || "-");
      document.getElementById("stat-sites").textContent =
        "Sites: " + p.sites_checked;
      document.getElementById("stat-suspicious").textContent =
        "Suspicious: " + p.suspicious_found;

      // Update status badge
      statusBadge.textContent = data.status;
      statusBadge.className = "badge badge-" + data.status;

      // CAPTCHA alert
      if (data.captcha_pending) {
        captchaAlert.style.display = "block";
      } else {
        captchaAlert.style.display = "none";
      }
    }

    if (data.type === "done") {
      source.close();
      statusBadge.textContent = data.status;
      statusBadge.className = "badge badge-" + data.status;
      captchaAlert.style.display = "none";
      progressBar.style.width = "100%";

      if (data.result_files && data.result_files.length > 0) {
        resultsCard.style.display = "block";
        resultsList.innerHTML = "";
        data.result_files.forEach(function (brand) {
          var item = document.createElement("div");
          item.className = "result-item";
          item.innerHTML =
            "<span>" +
            brand +
            "</span>" +
            '<a href="/api/jobs/' +
            jobId +
            "/results/" +
            brand +
            '" class="btn btn-sm">Download CSV</a>';
          resultsList.appendChild(item);
        });
      }
    }
  };

  source.onerror = function () {
    // SSE reconnects automatically, but if the job is done we close
    var badge = document.getElementById("job-status");
    if (
      badge &&
      (badge.textContent === "completed" || badge.textContent === "failed")
    ) {
      source.close();
    }
  };
}

// --- CAPTCHA ---
function solveCaptcha(jobId) {
  fetch("/api/jobs/" + jobId + "/captcha-solved", { method: "POST" })
    .then(function (r) {
      return r.json();
    })
    .then(function () {
      var alert = document.getElementById("captcha-alert");
      if (alert) alert.style.display = "none";
    });
}
