import {plugin, muxrpc} from 'secret-stack-decorators';
import {Discovery} from './types';
const broadcast = require('broadcast-stream');
const Ref = require('ssb-ref');
const Keys = require('ssb-keys');
const Notify = require('pull-notify');
const debug = require('debug')('ssb:lan');
const lanDiscoveryPort = require('../port');

const LEGACY_PORT = 8008;

@plugin('1.0.0')
class LAN {
  private readonly ssb: any;
  private readonly notifyDiscovery: any;
  private readonly caps: Buffer;
  private legacyBroadcast: any;
  private normalBroadcast: any;
  private int?: any;

  constructor(ssb: any, config: any) {
    this.ssb = ssb;
    this.notifyDiscovery = Notify();
    this.caps = Buffer.from(config.caps.shs, 'base64');
  }

  private readLegacy = (buf: any) => {
    if (buf.loopback) return;
    const address = buf.toString();
    const peer = Ref.parseAddress(address);
    if (peer && peer.key !== this.ssb.id) {
      this.notifyDiscovery({address, verified: false} as Discovery);
    }
  };

  private writeLegacy() {
    if (!this.legacyBroadcast) return;
    const address =
      this.ssb.getAddress('private') || this.ssb.getAddress('local');

    if (address) this.legacyBroadcast.write(address);
  }

  private readNormal = (buf: any) => {
    // split buf into [ciphertext,sig]
    const ciphertext = buf.slice(0, buf.length - 64);
    const sig = buf.slice(buf.length - 64, buf.length);

    // decrypt address
    let address: string;
    try {
      const obj = Keys.secretUnbox(ciphertext, this.caps);
      address = obj.address;
    } catch (err) {
      debug('failed to interpret broadcasted message: %s', buf.toString('hex'));
      return;
    }

    // validate address
    const peer = Ref.parseAddress(address);
    if (!peer) {
      debug(
        'failed to parse address from broadcasted message: %s',
        buf.toString('hex'),
      );
      return;
    }

    // avoid discovering ourselves
    if (peer.key === this.ssb.id) {
      return;
    }

    // verify signature of address
    const b64sig = sig.toString('base64') + '.sig.ed25519';
    const obj = {address, signature: b64sig};
    const verified = Keys.verifyObj({public: peer.key}, obj);

    // notify
    this.notifyDiscovery({address, verified} as Discovery);
  };

  private writeNormal() {
    if (!this.normalBroadcast) return;
    const address =
      this.ssb.getAddress('private') || this.ssb.getAddress('local');

    if (address) {
      // encrypt address
      const ciphertext = Keys.secretBox({address}, this.caps);

      // sign address
      const b64sig = Keys.signObj(this.ssb.keys, {address}).signature;
      const sig = Buffer.from(b64sig.replace(/\.sig\.ed25519$/, ''), 'base64');

      // concatenate [ciphertext,sig]
      const payload = Buffer.concat([ciphertext, sig]);

      // broadcast
      this.normalBroadcast.write(payload);
    }
  }

  private writeBoth = () => {
    this.writeLegacy();
    this.writeNormal();
  };

  @muxrpc('sync')
  public start = () => {
    try {
      this.normalBroadcast = broadcast(lanDiscoveryPort);
    } catch (err) {
      debug('LAN broadcast turned off because: %s', err);
      this.normalBroadcast = null;
    }

    try {
      this.legacyBroadcast = broadcast(LEGACY_PORT);
    } catch (err) {
      debug('legacy broadcast turned off because: %s', err);
      this.legacyBroadcast = null;
    }

    // Read
    if (this.normalBroadcast) this.normalBroadcast.on('data', this.readNormal);
    if (this.legacyBroadcast) this.legacyBroadcast.on('data', this.readLegacy);

    // Write now, then periodically
    this.writeBoth();
    this.int = setInterval(this.writeBoth, 2e3);
    if (this.int.unref) this.int.unref();
  };

  @muxrpc('sync')
  public stop = () => {
    clearInterval(this.int);
    this.normalBroadcast.close();
    this.normalBroadcast = null;
    this.legacyBroadcast.close();
    this.legacyBroadcast = null;
  };

  @muxrpc('source')
  public discoveredPeers = () => {
    return this.notifyDiscovery.listen();
  };
}

export = LAN;
