// ===== PhishGuard AI : main JavaScript =====
document.addEventListener("DOMContentLoaded", function () {

  // ---- Mobile menu ----
  var toggle = document.getElementById("navToggle");
  var links = document.getElementById("navLinks");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // ---- Print / save report as PDF ----
  var printBtn = document.querySelector("[data-print]");
  if (printBtn) {
    printBtn.addEventListener("click", function () { window.print(); });
  }

  // ---- Scanner page ----
  var form = document.getElementById("scanForm");
  if (!form) return;

  var urlInput = document.getElementById("urlInput");
  var urlError = document.getElementById("urlError");
  var fileInput = document.getElementById("shotInput");
  var fileError = document.getElementById("fileError");
  var preview = document.getElementById("preview");
  var dropText = document.getElementById("dropText");
  var dropLabel = document.getElementById("dropLabel");
  var loading = document.getElementById("loading");
  var MAX_BYTES = 5 * 1024 * 1024;

  function showError(el, message) {
    el.textContent = message;
    el.hidden = false;
  }
  function clearError(el) {
    el.textContent = "";
    el.hidden = true;
  }

  // Simple URL check (the server repeats a stricter check)
  function validateUrl(value) {
    value = value.trim();
    if (!value) return "Please enter a website URL.";
    if (/\s/.test(value)) return "The URL must not contain spaces.";
    if (/^(javascript|data|file|mailto|vbscript):/i.test(value)) return "Only http:// and https:// URLs can be analyzed.";
    if (value.indexOf("://") !== -1 && !/^https?:\/\//i.test(value)) return "Only http:// and https:// URLs can be analyzed.";
    var withScheme = /^https?:\/\//i.test(value) ? value : "https://" + value;
    try {
      var host = new URL(withScheme).hostname;
      if (host.indexOf(".") === -1 && !/^\[.*\]$/.test(host)) return "Please enter a valid domain name such as example.com.";
    } catch (e) {
      return "That does not look like a valid URL.";
    }
    return "";
  }

  // Check the screenshot file and show a preview
  function validateFile(file) {
    if (!file) return "";
    if (!/\.(png|jpe?g)$/i.test(file.name)) return "Only PNG and JPG screenshots are supported.";
    if (file.size > MAX_BYTES) return "The screenshot must be smaller than 5 MB.";
    return "";
  }

  fileInput.addEventListener("change", function () {
    clearError(fileError);
    var file = fileInput.files[0];
    var problem = validateFile(file);
    if (problem) {
      showError(fileError, problem);
      fileInput.value = "";
      preview.hidden = true;
      dropText.textContent = "Click to choose a PNG or JPG screenshot (max 5 MB)";
      dropLabel.classList.remove("has-file");
      return;
    }
    if (file) {
      dropText.textContent = "Selected: " + file.name;
      dropLabel.classList.add("has-file");
      var reader = new FileReader();
      reader.onload = function (e) { preview.src = e.target.result; preview.hidden = false; };
      reader.readAsDataURL(file);       // shown only as an <img>, never executed
    } else {
      preview.hidden = true;
    }
  });

  urlInput.addEventListener("input", function () { clearError(urlError); });

  form.addEventListener("submit", function (event) {
    clearError(urlError);
    clearError(fileError);
    var urlProblem = validateUrl(urlInput.value);
    var fileProblem = validateFile(fileInput.files[0]);
    if (urlProblem) showError(urlError, urlProblem);
    if (fileProblem) showError(fileError, fileProblem);
    if (urlProblem || fileProblem) {
      event.preventDefault();
      return;
    }
    loading.hidden = false;             // loading animation while the server works
  });

  // If the user comes back with the browser's Back button, hide the overlay
  window.addEventListener("pageshow", function () { loading.hidden = true; });
});