import crypto from 'crypto'

export default class {
  static async ssha_pass(passwd, salt) {
    const _ssha = (passwd, salt) => {
        const ctx = crypto.createHash('sha1');
        ctx.update(passwd, 'utf-8');
        ctx.update(salt, 'binary');
        const digest = ctx.digest('binary');
        const ssha = '{ssha}' + new Buffer(digest+salt,'binary').toString('base64');
        return ssha;
    }
    if(salt === undefined || salt === null) {
      let buf = await crypto.RandomBytes(32);
      return _ssha(passwd, buf.toString('base64'));
    } else {
      return _ssha(passwd, salt);
    }
  }

  static async checkssha(passwd, hash) {
    if (hash.substring(0,6).toLowerCase() != '{ssha}') {
        throw new Error('not {ssha}');
    }
    const bhash = new Buffer(hash.substr(6),'base64');
    const salt = bhash.toString('binary',20); // sha1 digests are 20 bytes long

    let newssha = await this.ssha_pass(passwd, salt);
    
    return (hash.substring(6) === newssha.substring(6));
  }
}
