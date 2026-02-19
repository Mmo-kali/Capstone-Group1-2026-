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
