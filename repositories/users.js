const fs = require('fs');
const crypto = require('crypto');
const util = require('util');

const Repository = require('./repository');

const scrypt = util.promisify(crypto.scrypt);

class UsersRepository extends Repository {
    
    async create(attributes) {
        // attributes = {email = '' , password = ''}
        attributes.id = this.randomId();

        const salt = crypto.randomBytes(8).toString('hex');
        const hashed = await scrypt(attributes.password, salt, 64);

        const records = await this.getAll();
        const record = {
            ...attributes,
            password: `${hashed.toString('hex')}.${salt}`
        };
        records.push(record);

        await this.writeAll(records);

        return record;

    }

    async comparePasswords(saved, supplied){
        // Saved -> password saved in the database. 'hashed.salt'
        // Supplied -> password given to us by user trying to sign in

        const [hashed, salt] = saved.split('.');
        const hashedSupplied = await scrypt(supplied, salt, 64);

        return hashed === hashedSupplied.toString('hex');

    }
}

module.exports = new UsersRepository('users.json');
