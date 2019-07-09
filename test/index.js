const tape = require('tape');
const Keys = require('ssb-keys');

const createSsbServer = require('ssb-server').use(require('../lib/index'));

tape('broadcasting looks correct', t => {
  var alice = createSsbServer({
    temp: 'test-lan-alice',
    timeout: 1000,
    port: 8008,
    keys: Keys.generate(),
  });
  alice.lan.start();

  setTimeout(() => {
    alice.lan.stop();
    t.end();
  }, 10e3);
});
