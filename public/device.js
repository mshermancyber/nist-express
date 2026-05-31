(function () {
  var ua = (navigator && navigator.userAgent) || '';
  var device = 'desktop';
  if (/iPad/i.test(ua)) device = 'desktop';
  else if (/Android/i.test(ua) && !/Mobile/i.test(ua)) device = 'desktop';
  else if (/iPhone|iPod/i.test(ua)) device = 'ios';
  else if (/Android/i.test(ua)) device = 'android';
  document.documentElement.setAttribute('data-device', device);
  window.deviceType = device;
})();
