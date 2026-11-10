// Sets the saved theme on <html> before first paint, so the page does not
// flash the stylesheet's default palette while the React bundle (a deferred
// module) loads. Loaded as a blocking classic script from index.html; it is
// a file rather than an inline <script> because the CSP is script-src 'self'.
//
// The storage key and fallback mirror THEME_KEY / DEFAULT_THEME in
// frontend/src/lib/appearance.ts, which validates the value and takes over
// once the bundle runs.
(function () {
  var theme = 'sandstone';
  try {
    var saved = localStorage.getItem('plexus-theme');
    if (saved && /^[a-z-]+$/.test(saved)) theme = saved;
  } catch (e) {
    /* storage unavailable: keep the default */
  }
  document.documentElement.setAttribute('data-theme', theme);
})();
