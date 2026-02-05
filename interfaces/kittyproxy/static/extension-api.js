/**
 * KittyProxy Extension API
 * Load this script in your UI extension to access flows and proxy API (same origin).
 * Example: <script src="/extension-api.js"></script>
 * Then use: KittyProxyAPI.getFlows(), KittyProxyAPI.getFlow(id), etc.
 */
(function () {
  'use strict';
  var base = '/api';

  function request(method, path, body) {
    var url = path.indexOf('http') === 0 ? path : base + path;
    var opts = { method: method || 'GET', headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    return fetch(url, opts).then(function (r) {
      if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
      var ct = r.headers.get('Content-Type') || '';
      return ct.indexOf('application/json') !== -1 ? r.json() : r.text();
    });
  }

  window.KittyProxyAPI = {
    /** GET /api/flows - list flows (paginated) */
    getFlows: function (page, size, search) {
      page = page || 1;
      size = size || 50;
      var q = '?page=' + page + '&size=' + size;
      if (search) q += '&search=' + encodeURIComponent(search);
      return request('GET', '/flows' + q);
    },
    /** GET /api/flows/{id} - get one flow (request/response) */
    getFlow: function (flowId) {
      return request('GET', '/flows/' + encodeURIComponent(flowId));
    },
    /** POST /api/clear - clear all flows */
    clearFlows: function () {
      return request('POST', '/clear');
    },
    /** GET /api/endpoints - discovered endpoints */
    getEndpoints: function () {
      return request('GET', '/endpoints');
    },
    /** POST /api/replay/{flow_id} - replay a flow */
    replay: function (flowId) {
      return request('POST', '/replay/' + encodeURIComponent(flowId));
    },
    /** POST /api/send_custom - send custom request (body: { method, url, headers?, body? }) */
    sendRequest: function (opts) {
      return request('POST', '/send_custom', opts);
    },
    /** GET /api/intercept/pending - list flows waiting in intercept */
    getInterceptPending: function () {
      return request('GET', '/intercept/pending');
    },
    /** POST /api/intercept/{flow_id}/resume - resume intercepted flow (body: { request?, response? }) */
    resumeIntercept: function (flowId, data) {
      return request('POST', '/intercept/' + encodeURIComponent(flowId) + '/resume', data || {});
    },
    /** Raw request for any other endpoint */
    request: request,
    base: base
  };
})();
