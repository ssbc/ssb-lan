const tape = require('tape');
const Keys = require('ssb-keys');
const broadcast = require('broadcast-stream');
const port = require('../port');

const createSsbServer = require('ssb-server').use(require('../lib/index'));

tape('broadcasting looks correct', t => {
  t.plan(7);

  const keys = Keys.generate();
  const alice = createSsbServer({
    temp: 'test-lan-alice',
    timeout: 1000,
    port: 8008,
    keys,
  });
  alice.lan.start();

  const b = broadcast(port);
  b.on('data', buf => {
    const msg = JSON.parse(buf.toString());

    t.equals(typeof msg.address, 'string', 'address is a string');
    t.ok(msg.address, 'address is okay');
    t.equals(msg.address.slice(0, 4), 'net:', 'address begins with net:');

    t.equals(typeof msg.capsHash, 'string', 'capsHash is a string');
    t.ok(msg.capsHash, 'capsHash is okay');

    t.equals(typeof msg.signature, 'string', 'signature is a string');
    t.ok(msg.signature, 'signature is okay');

    b.close();
    alice.lan.stop();
    alice.close();
    t.end();
  });
});
