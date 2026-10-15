(function (scope, post) {
  // The path tracer of an exported topology file: starts Pyodide from the
  // blocks the file carries (no network: every file the runtime asks for is
  // answered from memory), loads the engine's modules and the trace inputs,
  // and answers trace requests. Runs in a worker made from a blob (classic,
  // else module), or on the page when no worker can start. Messages in: {type: 'init', files,
  // modules, inputs} once, then {type: 'trace', id, request}. Out: 'ready',
  // 'error', and 'result' or 'failed' per trace.
  'use strict';
  var BASE = 'https://plexus.invalid/pyodide/';
  var assets = {}, run = null, stage = 'runtime';
  function now() { return scope.performance.now(); }
  function message(err) { return String((err && err.message) || err || 'unknown error'); }
  function decode(text) {
    if (typeof Uint8Array.fromBase64 === 'function') return Uint8Array.fromBase64(text.trim());
    var bin = scope.atob(text.trim()), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function gunzip(text) {
    var stream = new Blob([decode(text)]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(stream).arrayBuffer().then(function (buffer) { return new Uint8Array(buffer); });
  }
  function moduleUrl(bytes) { return URL.createObjectURL(new Blob([bytes], { type: 'text/javascript' })); }
  // Pyodide reads its WebAssembly binary, standard library and package lock
  // with fetch() under indexURL: those names are answered from the file.
  function serve(input) {
    var url = String(input && input.url ? input.url : input);
    var name = url.indexOf(BASE) === 0 ? url.slice(BASE.length) : '';
    var asset = assets[name];
    if (!asset) return Promise.reject(new TypeError('The path tracer loads nothing from the network: ' + url));
    return Promise.resolve(new Response(asset.bytes, { status: 200, headers: { 'Content-Type': asset.type } }));
  }
  // Pyodide refuses a classic worker, which it detects by importScripts()
  // working; this runtime loads it with import() instead, so importScripts
  // is turned off while it starts.
  function noImportScripts() { throw new TypeError('importScripts is not used by the path tracer'); }
  function start(msg) {
    var began = now(), loaded = 0, fetchBefore = scope.fetch, importBefore = scope.importScripts;
    return Promise.all(Object.keys(msg.files).map(function (name) {
      return gunzip(msg.files[name].data).then(function (bytes) { assets[name] = { bytes: bytes, type: msg.files[name].type }; });
    })).then(function () {
      scope.fetch = serve;
      if (typeof importBefore === 'function') scope.importScripts = noImportScripts;
      return Promise.all([import(moduleUrl(assets['pyodide.asm.mjs'].bytes)), import(moduleUrl(assets['pyodide.mjs'].bytes))]);
    }).then(function (mods) {
      var lock = JSON.parse(new TextDecoder().decode(assets['pyodide-lock.json'].bytes));
      return mods[1].loadPyodide({ indexURL: BASE, createPyodideModule: mods[0].default, lockFileContents: lock,
        packages: [], stdout: function () {}, stderr: function () {} });
    }).then(function (pyodide) {
      scope.fetch = fetchBefore;
      if (typeof importBefore === 'function') scope.importScripts = importBefore;
      assets = {};
      loaded = now();
      stage = 'tracer';
      return Promise.all([gunzip(msg.modules), gunzip(msg.inputs)]).then(function (parts) {
        var FS = pyodide.FS, sources = JSON.parse(new TextDecoder().decode(parts[0]));
        Object.keys(sources).forEach(function (path) {
          var file = '/plexus/' + path;
          FS.mkdirTree(file.slice(0, file.lastIndexOf('/')));
          FS.writeFile(file, sources[path]);
        });
        FS.writeFile('/plexus/inputs.json', parts[1]);
        pyodide.runPython('import sys\nsys.path.insert(0, "/plexus")\n' +
          'from netcontrol.integrations.pathtrace import offline\n' +
          '_plexus_trace = offline.open_session("/plexus/inputs.json")\n');
        FS.unlink('/plexus/inputs.json');
        run = pyodide.globals.get('_plexus_trace');
        post({ type: 'ready', load_ms: Math.round(loaded - began), build_ms: Math.round(now() - loaded),
          version: pyodide.version });
      });
    });
  }
  return function (msg) {
    if (!msg) return;
    if (msg.type === 'init') {
      start(msg).catch(function (err) { post({ type: 'error', stage: stage, message: message(err) }); });
    } else if (msg.type === 'trace') {
      var began = now();
      try {
        var result = run(JSON.stringify(msg.request));
        post({ type: 'result', id: msg.id, ms: Math.round(now() - began), result: result });
      } catch (err) {
        post({ type: 'failed', id: msg.id, message: message(err) });
      }
    }
  };
})
