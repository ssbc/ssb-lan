import {plugin, muxrpc} from 'secret-stack-decorators';
const broadcast = require('broadcast-stream');
const Ref = require('ssb-ref');
const Keys = require('ssb-keys');
const Notify = require('pull-notify');
const debug = require('debug')('ssb:lan');
const lanDiscoveryPort = require('../port');

type Discovery = {
  verified: boolean;
  address: string;
  capsHash: string | null;
};

@plugin('1.0.0')
class LAN {
  private readonly ssb: any;
  private readonly config: any;
  private readonly notifyDiscovery: any;
  private legacyBroadcast: any;
  private normalBroadcast: any;
  private int?: any;

  constructor(ssb: any, config: any) {
    this.ssb = ssb;
    this.config = config;
    this.notifyDiscovery = Notify();
  }

  private readLegacy = (buf: any) => {
    if (buf.loopback) return;
    const address = buf.toString();
    const peer = Ref.parseAddress(address);
    if (peer && peer.key !== this.ssb.id) {
      const disc: Discovery = {
        address: address,
        verified: false,
        capsHash: null,
      };
      this.notifyDiscovery(disc);
    }
  };

  private writeLegacy() {
    if (!this.legacyBroadcast) return;
    const address =
      this.ssb.getAddress('private') || this.ssb.getAddress('local');

    if (address) this.legacyBroadcast.write(address);
  }

  private readNormal = (buf: any) => {
    if (buf.loopback) return;

    const msg = buf.toString();

    let parsed: {[name: string]: string};
    try {
      parsed = JSON.parse(msg);
    } catch (err) {
      debug('failed to interpret broadcasted message: %s', msg);
      return;
    }
    const {address, capsHash, signature} = parsed;

    const peer = Ref.parseAddress(address);
    if (!peer) {
      debug('failed to parse address from broadcasted message: %s', msg);
      return;
    }

    if (peer.key === this.ssb.id) {
      return;
    }

    const obj = {address, signature};
    const verified = Keys.verifyObj({public: peer.key}, obj);

    const disc: Discovery = {address, verified, capsHash};
    this.notifyDiscovery(disc);
  };

  private writeNormal() {
    if (!this.normalBroadcast) return;
    const address =
      this.ssb.getAddress('private') || this.ssb.getAddress('local');

    if (address) {
      const caps = this.config.caps.shs;
      const capsHash = Keys.hash(caps);
      const obj = {address};
      const signature = Keys.signObj(this.ssb.keys.private, obj).signature;
      const msg = JSON.stringify({address, capsHash, signature});
      this.normalBroadcast.write(msg);
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
      this.legacyBroadcast = broadcast(this.config.port);
    } catch (err) {
      debug('legacy broadcast turned off because: %s', err);
      this.legacyBroadcast = null;
    }

    // Read
    if (this.normalBroadcast) this.normalBroadcast.on('data', this.readNormal);
    if (this.legacyBroadcast) this.legacyBroadcast.on('data', this.readLegacy);

    // Write now, then periodically
    this.writeBoth();
    this.int = setInterval(this.writeBoth, 2000);
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
