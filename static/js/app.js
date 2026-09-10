/**
 * app.js - Client-side interaction logic for Network Security IP Range Scanner.
 * Project 3: College Cybersecurity Assignment Prototype
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const scanForm = document.getElementById("scan-form");
  const ipInput = document.getElementById("ip-range-input");
  const clearBtn = document.getElementById("clear-btn");
  const scanBtn = document.getElementById("scan-btn");
  const btnSpinner = document.getElementById("btn-spinner");
  const btnIcon = document.getElementById("btn-icon");
  const btnText = document.getElementById("btn-text");

  const progressSection = document.getElementById("scanning-progress");
  const progressTargetText = document.getElementById("progress-target-text");

  const errorBanner = document.getElementById("error-banner");
  const errorMessage = document.getElementById("error-message");
  const dismissError = document.getElementById("dismiss-error");

  const statTotal = document.getElementById("stat-total");
  const statActive = document.getElementById("stat-active");
  const statInactive = document.getElementById("stat-inactive");
  const statDuration = document.getElementById("stat-duration");

  const resultsCount = document.getElementById("results-count");
  const resultsTbody = document.getElementById("results-tbody");
  const filterBtns = document.querySelectorAll(".filter-btn");
  const filterAllCount = document.getElementById("filter-all-count");
  const filterActiveCount = document.getElementById("filter-active-count");
  const filterInactiveCount = document.getElementById("filter-inactive-count");

  const presetChips = document.querySelectorAll(".preset-chip");

  // State
  let scanResults = [];
  let currentFilter = "all";

  // Quick Presets Handler
  presetChips.forEach(chip => {
    chip.addEventListener("click", () => {
      const presetVal = chip.getAttribute("data-preset");
      if (presetVal) {
        ipInput.value = presetVal;
        ipInput.focus();
        clearError();
      }
    });
  });

  // Clear Input Button
  clearBtn.addEventListener("click", () => {
    ipInput.value = "";
    ipInput.focus();
  });

  // Dismiss Error Alert
  dismissError.addEventListener("click", () => {
    clearError();
  });

  function showError(msg) {
    errorMessage.textContent = msg;
    errorBanner.hidden = false;
  }

  function clearError() {
    errorBanner.hidden = true;
    errorMessage.textContent = "";
  }

  // Filter switching
  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.getAttribute("data-filter");
      renderTable();
    });
  });

  // Render Table
  function renderTable() {
    let filtered = scanResults;
    if (currentFilter === "Active") {
      filtered = scanResults.filter(h => h.status === "Active");
    } else if (currentFilter === "Inactive") {
      filtered = scanResults.filter(h => h.status === "Inactive");
    }

    if (!scanResults.length) {
      resultsTbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="5">
            <div class="empty-state">
              <div class="empty-icon">📡</div>
              <h4>No scan executed yet</h4>
              <p>Enter an IP range above and click <strong>Start Scan</strong> to begin host discovery.</p>
            </div>
          </td>
        </tr>
      `;
      resultsCount.textContent = "0 hosts detected";
      return;
    }

    if (!filtered.length) {
      resultsTbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="5">
            <div class="empty-state">
              <div class="empty-icon">🔍</div>
              <h4>No hosts match current filter</h4>
              <p>Try selecting <strong>All</strong> to view all ${scanResults.length} scanned hosts.</p>
            </div>
          </td>
        </tr>
      `;
      resultsCount.textContent = `Showing 0 of ${scanResults.length} hosts`;
      return;
    }

    resultsCount.textContent = `Showing ${filtered.length} of ${scanResults.length} hosts`;

    resultsTbody.innerHTML = filtered.map((host, index) => {
      const isActive = host.status === "Active";
      const statusBadge = isActive
        ? `<span class="status-badge active">Active</span>`
        : `<span class="status-badge inactive">Inactive</span>`;

      const latencyCell = (isActive && host.latency_ms !== null)
        ? `<span class="latency-val">${host.latency_ms} ms</span>`
        : `<span class="latency-na">Timed out</span>`;

      return `
        <tr>
          <td style="color: var(--text-muted); font-family: var(--font-mono);">${index + 1}</td>
          <td>
            <div class="ip-cell">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--text-muted);">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                <line x1="6" y1="18" x2="6.01" y2="18"></line>
              </svg>
              <span>${escapeHtml(host.ip)}</span>
            </div>
          </td>
          <td>${statusBadge}</td>
          <td>${latencyCell}</td>
          <td><span class="protocol-tag">ICMP Echo (Ping)</span></td>
        </tr>
      `;
    }).join("");
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Handle Form Submit
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    const targetVal = ipInput.value.trim();
    if (!targetVal) {
      showError("Please specify an IP address, range, or CIDR subnet.");
      return;
    }

    // Set UI Loading state
    scanBtn.disabled = true;
    btnSpinner.hidden = false;
    btnIcon.hidden = true;
    btnText.textContent = "Scanning...";

    progressTargetText.textContent = `Probing ${targetVal} with concurrent ICMP ping requests...`;
    progressSection.hidden = false;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ target: targetVal })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        const errorMsg = data.error || `Scan failed with status ${response.status}`;
        showError(errorMsg);
        return;
      }

      // Update Summary Cards
      statTotal.textContent = data.summary.total;
      statActive.textContent = data.summary.active;
      statInactive.textContent = data.summary.inactive;
      statDuration.textContent = `${data.summary.duration_seconds}s`;

      // Update Filter counts
      filterAllCount.textContent = data.summary.total;
      filterActiveCount.textContent = data.summary.active;
      filterInactiveCount.textContent = data.summary.inactive;

      // Update Results
      scanResults = data.hosts || [];
      renderTable();

    } catch (err) {
      showError(`Network connection error: ${err.message}. Ensure the Flask server is running.`);
    } finally {
      // Revert UI Loading state
      scanBtn.disabled = false;
      btnSpinner.hidden = true;
      btnIcon.hidden = false;
      btnText.textContent = "Start Scan";
      progressSection.hidden = true;
    }
  });
});
