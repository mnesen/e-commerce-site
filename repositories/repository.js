const fs = require('fs');
const crypto = require('crypto');


module.exports = class Repository {

    constructor(filename){
        if(!filename){
            throw new Error('Filename required when creating a repository.');
        }

        this.filename = filename;

        try{
            fs.accessSync(filename);
        } catch(err){
            fs.writeFileSync(filename, '[]');
        } 
    }

    async create(attributes){
        attributes.id = this.randomId();

        const records = await this.getAll();
        records.push(attributes);

        await this.writeAll(records);

        return attributes;
    }

    async getAll(){

        const contents =  JSON.parse(await fs.promises.readFile(this.filename,{encoding:'utf8'}));

        // Return the parsed data
        return contents
    }


    async writeAll(records){
        await fs.promises.writeFile(this.filename, JSON.stringify(records, null, 2));
    }

    randomId(){
        return crypto.randomBytes(4).toString('hex');

    }

    async getOne(id){
        const records = await this.getAll();

        return records.find(record => record.id === id);
    }

    async delete(id){
        const records = await this.getAll();
        const filteredRecords = records.filter(record => record.id !== id);
        await this.writeAll(filteredRecords);
    }

    async update(id, attributes){
        const records = await this.getAll();
        const record = records.find(record => record.id === id);

        if(!record){
            throw new Error(`The record with id ${id} was not found`);
        }

        Object.assign(record,attributes);

        await this.writeAll(records);
    }

    async getOneBy(filters){
        const records = await this.getAll();

        for(let record of records){
            let found = true;

            for(let key in filters){
                if(record[key] !== filters[key]){
                    found = false;
                }
            }

            if(found){
                return record;
            }
        }
    }



}