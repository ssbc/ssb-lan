# ssb-lan

SSB plugin for discovery of other peers in the same LAN. Works by broadcasting UDP packets to all other peers in the local network. **Is backwards-compatible** with [ssb-local](https://github.com/ssbc/ssb-local).

## Usage

**Prerequisites:**

- Requires **Node.js 6.5** or higher
- Requires `secret-stack@^6.2.0`

```
npm install --save ssb-lan
```

Add this plugin to ssb-server like this:

```diff
 var createSsbServer = require('ssb-server')
     .use(require('ssb-onion'))
     .use(require('ssb-unix-socket'))
     .use(require('ssb-no-auth'))
     .use(require('ssb-plugins'))
     .use(require('ssb-master'))
     .use(require('ssb-conn'))
+    .use(require('ssb-lan'))
     .use(require('ssb-replicate'))
     .use(require('ssb-friends'))
     // ...
```

Now you should be able to access the following muxrpc APIs under `ssb.lan.*`:

| API | Type | Description |
|-----|------|-------------|
| **`start()`** | `sync` | Triggers the start of LAN discovery of peers. |
| **`stop()`** | `sync` | Stops the LAN discovery of peers if it is currently active. |
| **`discoveredPeers()`** | `source` | A pull-stream that emits "discovery objects" (see definition below) every time a peer is (re)discovered on the local area network. |

A "discovery" is an object with the following shape:

```typescript
type Discovery = {
  address: string;
  capsHash: string | null;
  verified: boolean;
};
```

- **address**: this is a [multiserver address](https://github.com/dominictarr/multiserver-address) that the remote peer is declaring to us in the LAN
- **capsHash**: this is a sha256 hash of the secret-handshake "caps" adopted and broadcasted by the remote peer. Is null when the remote peer did not announce this field, perhaps because they used the legacy ssb-local
- **verified**: this is a boolean indicating whether we are cryptographically sure the remote peer is not spoofing their multiserver address, and that they actually own the ed25519 identity which they announced

## License

MIT
