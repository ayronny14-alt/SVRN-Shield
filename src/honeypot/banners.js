/**
 * Fake service banners that mimic real services just enough to waste attacker time
 * and fingerprint their tooling.
 */

const BANNERS = {
  ssh: {
    greeting: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n',
    respond(data) {
      // absorb key exchange attempts, respond with plausible garbage
      if (data.length > 0 && data[0] === 0x14) {
        // SSH_MSG_KEXINIT — respond with our own fake KEXINIT
        const resp = Buffer.alloc(64);
        resp[0] = 0x14; // SSH_MSG_KEXINIT
        resp.fill(0x41, 1, 17); // fake cookie
        return resp;
      }
      return null;
    },
    proto: 'tcp',
  },

  http: {
    greeting: null,
    respond(data) {
      const req = data.toString('utf8', 0, Math.min(data.length, 512));
      if (req.startsWith('GET') || req.startsWith('POST') || req.startsWith('HEAD')) {
        return Buffer.from(
          'HTTP/1.1 200 OK\r\n' +
          'Server: nginx/1.24.0\r\n' +
          'Content-Type: text/html\r\n' +
          'Content-Length: 162\r\n' +
          'Connection: close\r\n\r\n' +
          '<!DOCTYPE html><html><head><title>Welcome</title></head>' +
          '<body><h1>It works!</h1><p>Default web page.</p></body></html>'
        );
      }
      return null;
    },
    proto: 'tcp',
  },

  https: {
    greeting: null,
    respond(data) {
      // TLS ClientHello — respond with a ServerHello-like record that looks plausible
      if (data.length >= 5 && data[0] === 0x16 && data[1] === 0x03) {
        const alert = Buffer.from([
          0x15,       // Alert record
          0x03, 0x03, // TLS 1.2
          0x00, 0x02, // length
          0x02, 0x28, // fatal, handshake failure
        ]);
        return alert;
      }
      return null;
    },
    proto: 'tcp',
  },

  ftp: {
    greeting: '220 (vsFTPd 3.0.5)\r\n',
    respond(data) {
      const cmd = data.toString('utf8').trim().toUpperCase();
      if (cmd.startsWith('USER')) return Buffer.from('331 Please specify the password.\r\n');
      if (cmd.startsWith('PASS')) return Buffer.from('530 Login incorrect.\r\n');
      if (cmd === 'QUIT') return Buffer.from('221 Goodbye.\r\n');
      if (cmd === 'SYST') return Buffer.from('215 UNIX Type: L8\r\n');
      return Buffer.from('500 Unknown command.\r\n');
    },
    proto: 'tcp',
  },

  smtp: {
    greeting: '220 mail.example.com ESMTP Postfix (Ubuntu)\r\n',
    respond(data) {
      const cmd = data.toString('utf8').trim().toUpperCase();
      if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) {
        return Buffer.from(
          '250-mail.example.com\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 OK\r\n'
        );
      }
      if (cmd.startsWith('MAIL FROM')) return Buffer.from('250 OK\r\n');
      if (cmd.startsWith('RCPT TO')) return Buffer.from('550 User not found\r\n');
      if (cmd === 'QUIT') return Buffer.from('221 Bye\r\n');
      return Buffer.from('502 Command not implemented\r\n');
    },
    proto: 'tcp',
  },

  telnet: {
    greeting: Buffer.from([
      0xFF, 0xFD, 0x18, // DO Terminal Type
      0xFF, 0xFD, 0x20, // DO Terminal Speed
      0xFF, 0xFD, 0x23, // DO X Display Location
    ]),
    respond(data) {
      if (!this._sentLogin) {
        this._sentLogin = true;
        return Buffer.from('\r\nUbuntu 22.04.3 LTS\r\nlogin: ');
      }
      if (!this._sentPassword) {
        this._sentPassword = true;
        return Buffer.from('Password: ');
      }
      return Buffer.from('\r\nLogin incorrect\r\nlogin: ');
    },
    proto: 'tcp',
    _sentLogin: false,
    _sentPassword: false,
  },

  mysql: {
    greeting: (() => {
      // simplified MySQL greeting packet
      const version = 'mysql_native_password';
      const buf = Buffer.alloc(78);
      buf.writeUInt32LE(74, 0); // packet length + seq
      buf[3] = 0; // seq
      buf[4] = 10; // protocol version
      buf.write('8.0.35\0', 5); // server version
      buf.writeUInt32LE(12345, 12); // connection id
      return buf;
    })(),
    respond(data) {
      // respond to auth with ACCESS DENIED
      const err = Buffer.alloc(64);
      err.writeUInt32LE(60, 0);
      err[3] = 2;
      err.writeUInt16LE(0xFF, 4); // ERR packet
      err.writeUInt16LE(1045, 5); // error code
      err.write('#28000', 7); // sql state marker
      err.write('Access denied', 13);
      return err;
    },
    proto: 'tcp',
  },

  redis: {
    greeting: null,
    respond(data) {
      const cmd = data.toString('utf8').trim();
      if (cmd === 'PING') return Buffer.from('+PONG\r\n');
      if (cmd.startsWith('AUTH')) return Buffer.from('-ERR invalid password\r\n');
      if (cmd.startsWith('INFO')) return Buffer.from('-NOAUTH Authentication required.\r\n');
      return Buffer.from('-ERR unknown command\r\n');
    },
    proto: 'tcp',
  },

  dns: {
    greeting: null,
    respond(data) {
      // respond to DNS queries with NXDOMAIN
      if (data.length < 12) return null;
      const resp = Buffer.from(data);
      resp[2] = 0x81; // QR=1, RD=1
      resp[3] = 0x83; // NXDOMAIN
      return resp;
    },
    proto: 'udp',
  },
};

export function getBanner(service) {
  const b = BANNERS[service];
  if (!b) return null;
  return { ...b, _sentLogin: false, _sentPassword: false };
}

export function listBanners() {
  return Object.keys(BANNERS);
}

export function createBanner(name, config) {
  BANNERS[name] = config;
}

export { BANNERS };
