// Progressive enhancement only (ARCH-006 §3.2, §4 row 6). The server owns all
// business logic and every state change still POSTs to the server; this module
// only refreshes the P1/P2 SLA-countdown fragment in place so a countdown tick
// never triggers a full page reload. No inline handlers, no business rules.
(function () {
  "use strict";

  var PANEL = ".sla-panel";

  function refreshSLA() {
    var panel = document.querySelector(PANEL);
    if (!panel) {
      return;
    }
    var endpoint = panel.getAttribute("data-sla-endpoint");
    if (!endpoint) {
      return;
    }
    fetch(endpoint, {
      headers: { "X-Requested-With": "risksignal-progressive" },
      credentials: "same-origin",
    })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error("SLA fragment " + resp.status);
        }
        return resp.text();
      })
      .then(function (html) {
        var current = panel.querySelector("#sla-countdowns");
        if (current) {
          current.outerHTML = html;
        } else {
          panel.insertAdjacentHTML("beforeend", html);
        }
      })
      .catch(function () {
        /* A failed tick is non-fatal: the last rendered countdown stays. */
      });
  }

  if (document.querySelector(PANEL)) {
    window.setInterval(refreshSLA, 30000);
  }
})();
