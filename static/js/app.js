document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-confirm]").forEach((el) => {
    el.addEventListener("click", (event) => {
      const form = el.closest("form");
      if (!form || form.dataset.confirmed === "true") return;
      event.preventDefault();
      const modalEl = document.getElementById("confirmModal");
      const modal = new bootstrap.Modal(modalEl);
      document.getElementById("confirmSubmit").onclick = () => {
        form.dataset.confirmed = "true";
        form.requestSubmit();
      };
      modal.show();
    });
  });
});
