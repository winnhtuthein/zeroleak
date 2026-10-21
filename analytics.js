/*
 * ZeroLeak
 * Copyright (C) 2026 Winn Htut Hein
 * SPDX-License-Identifier: AGPL-3.0-or-later. See LICENSE and NOTICE.
 */

/* Vercel Web Analytics loader (cookieless, page views only).
 *
 * This file is deliberately separate from app.js and engine.js. Those two never
 * touch the network (tests/site.test.js enforces it). This is the only file in
 * the project that causes a request, and it can never see your code: it does not
 * read the editors, the clipboard or any other page content.
 *
 * To remove analytics entirely: delete the <script src="analytics.js"> tag from
 * each page. Nothing else depends on it.
 *
 * It stays off when:
 *   - the browser sends Do Not Track or Global Privacy Control,
 *   - the page is opened from disk (file:) or served from localhost / a LAN name,
 *   - it is not running over https.
 * Vercel only serves /_vercel/insights/script.js once Web Analytics is enabled
 * for the project in the Vercel dashboard (Analytics tab, Enable).
 */
(function () {
  "use strict";

  var nav = window.navigator || {};
  var loc = window.location;

  function optedOut() {
    return (
      nav.doNotTrack === "1" || nav.doNotTrack === "yes" ||
      window.doNotTrack === "1" || nav.msDoNotTrack === "1" ||
      nav.globalPrivacyControl === true
    );
  }

  function isLocal(host) {
    return (
      host === "" || host === "localhost" || host === "[::1]" ||
      /^127\./.test(host) || /^(10|192\.168)\./.test(host) || /\.local$/.test(host)
    );
  }

  if (loc.protocol !== "https:" || isLocal(loc.hostname) || optedOut()) return;

  // Vercel's documented plain-HTML snippet: a queue stub, then the deferred script.
  window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };

  var s = document.createElement("script");
  s.defer = true;
  s.src = "/_vercel/insights/script.js";
  document.head.appendChild(s);
})();
