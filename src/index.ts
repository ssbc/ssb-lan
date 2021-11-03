import {plugin, muxrpc} from 'secret-stack-decorators';
import {Discovery, SSBConfig} from './types';
const broadcast = require('broadcast-stream');
const Ref = require('ssb-ref');
const Keys = require('ssb-keys');
const pull = require('pull-stream');
const Notify = require('pull-notify');
const debug = require('debug')('ssb:lan');

const NORMAL_PORT = require('../port');
const LEGACY_PORT = 8008;

@plugin('1.1.0')
class LAN {
  private readonly ssb: Record<string, any>;
  private readonly caps: Buffer;
  private readonly legacyEnabled: boolean;
  private notifyDiscovery?: CallableFunction & Record<string, any>;
  private legacyBroadcast?: Record<string, any>;
  private normalBroadcast?: Record<string, any>;
  private int?: any;

  constructor(ssb: Record<string, any>, config: SSBConfig) {
    this.ssb = ssb;
    this.notifyDiscovery = void 0;
    this.caps = Buffer.from(config.caps.shs, 'base64');
    this.legacyEnabled = config.lan?.legacy !== false;
  }

  private readLegacy = (buf: any) => {
    if (buf.loopback) return;
    const address = buf.toString();
    const peerKey = Ref.getKeyFromAddress(address);
    if (peerKey && peerKey !== this.ssb.id) {
      this.notifyDiscovery!({address, verified: false} as Discovery);
    }
  };

  private writeLegacy() {
    if (!this.legacyBroadcast) return;
    const address =
      this.ssb.getAddress('private') ?? this.ssb.getAddress('local');

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
    const peerKey = Ref.getKeyFromAddress(address);
    if (!peerKey) {
      debug(
        'failed to parse address from broadcasted message: %s',
        buf.toString('hex'),
      );
      return;
    }

    // avoid discovering ourselves
    if (peerKey === this.ssb.id) {
      return;
    }

    // verify signature of address
    const b64sig = sig.toString('base64') + '.sig.ed25519';
    const obj = {address, signature: b64sig};
    const verified = Keys.verifyObj({public: peerKey}, obj);

    // notify
    this.notifyDiscovery!({address, verified} as Discovery);
  };

  private writeNormal() {
    if (!this.normalBroadcast) return;
    const address =
      this.ssb.getAddress('private') ?? this.ssb.getAddress('local');

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
    this.notifyDiscovery = Notify();

    try {
      this.normalBroadcast = broadcast(NORMAL_PORT);
    } catch (err) {
      debug('LAN broadcast turned off because: %s', err);
      this.normalBroadcast = void 0;
    }

    try {
      this.legacyBroadcast = this.legacyEnabled
        ? broadcast(LEGACY_PORT)
        : void 0;
    } catch (err) {
      debug('legacy broadcast turned off because: %s', err);
      this.legacyBroadcast = void 0;
    }

    // Read
    if (this.normalBroadcast) this.normalBroadcast.on('data', this.readNormal);
    if (this.legacyBroadcast) this.legacyBroadcast.on('data', this.readLegacy);

    // Write now, then periodically
    this.writeBoth();
    this.int = setInterval(this.writeBoth, 2e3);
    this.int?.unref?.();

    // Setup to call `stop` automatically when ssb is closed
    const that = this;
    this.ssb.close.hook(function (this: any, fn: any, args: any) {
      that.stop();
      fn.apply(this, args);
    });
  };

  @muxrpc('sync')
  public stop = () => {
    clearInterval(this.int);
    this.notifyDiscovery?.end();
    this.notifyDiscovery = void 0;
    this.normalBroadcast?.close();
    this.normalBroadcast = void 0;
    this.legacyBroadcast?.close();
    this.legacyBroadcast = void 0;
  };

  @muxrpc('source')
  public discoveredPeers = () => {
    if (this.notifyDiscovery) return this.notifyDiscovery.listen();
    else return pull.empty();
  };
}

export = LAN;
