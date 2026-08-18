(function () {
  var saved = localStorage.getItem('sentrylite-theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);
  var btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', cur);
      localStorage.setItem('sentrylite-theme', cur);
    });
  }
})();
