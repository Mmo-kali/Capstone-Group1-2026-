// ── Theme Management ──
function initializeTheme() {
  const html = document.documentElement;
  const themeToggle = document.getElementById("theme-toggle");
  
  // Get saved theme preference or system preference
  let theme = localStorage.getItem("theme");
  
  if (!theme) {
    // Check system preference
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    theme = prefersDark ? "dark" : "light";
  }
  
  // Apply theme
  html.setAttribute("data-theme", theme);
  
  // Theme toggle handler
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      const currentTheme = html.getAttribute("data-theme");
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      html.setAttribute("data-theme", newTheme);
      localStorage.setItem("theme", newTheme);
    });
  }
}

document.addEventListener("DOMContentLoaded", initializeTheme);

// ── Sidebar toggle ──
document.addEventListener("DOMContentLoaded", function () {
  const sidebarToggle = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("sidebar");

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener("click", function () {
      sidebar.classList.toggle("collapsed");
      localStorage.setItem("sidebarCollapsed", sidebar.classList.contains("collapsed"));
    });

    // Restore sidebar state on page load
    if (localStorage.getItem("sidebarCollapsed") === "true") {
      sidebar.classList.add("collapsed");
    }
  }
});

// ── Tab switching ──
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".tab-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var card = btn.closest(".card");

      // Deactivate all tabs & panels within this card
      card.querySelectorAll(".tab-btn").forEach(function (b) { b.classList.remove("active"); });
      card.querySelectorAll(".tab-content").forEach(function (tc) { tc.classList.remove("active"); });

      // Activate clicked tab & matching panel
      btn.classList.add("active");
      card.querySelector("#" + btn.dataset.tab).classList.add("active");
    });
  });
});
