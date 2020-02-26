# webunpack
> A recon tool for security purposes  
> Find the vulnerable modules inside webpack.js files (bundles)

---
## Installation
Install globally [webpack](https://webpack.js.org/) and webpack-cli:
```shell
npm install --global webpack
npm install --global webpack-cli
```

## CLI example
Download the latest [release](https://github.com/eric-therond/webunpack/releases) of webunpack or git clone this repository.  
To display the help:
```shell
node webpack.js
```

To fetch the list of vulnerable npm modules:
```shell
node webunpack.js getvulns > vulnerablemodules.txt
```

To create a signatures database from vulnerable npm modules:  
(**warning**: creation of database could take several days it is recommended to use precomputed database in [dbs folder](./dbs/))
```shell
node webunpack.js createdb vulnerablemodules.txt ./dbs/signaturesdb.json
```

To update a signatures database from vulnerable npm modules:
```shell
node webunpack.js updatedb vulnerablemodules.txt ./dbs/signaturesdb.json
```

To filter signatures/remove duplicate signatures shared between modules:
```shell
cp ./dbs/signaturesdb.json ./dbs/signaturesdbfiltered.json
node webunpack.js filterdb vulnerablemodules.txt ./dbs/signaturesdbfiltered.json
```

To retrieve vulnerable npm modules from a packed file:
```shell
node webunpack.js unpack ./dbs/signaturesdbfiltered.json ./tests/testhandlebarsvuln/dist/main.js
```

## API example
Update your package.json to use webunpack:
```javascript
{
  "name": "test",
  "version": "0.0.1",
  "license": "MIT",
  "dependencies": {
    "webunpack.js": "^0.0.2"
  }
}

```
Unpack a file with unpackFile method:
```javascript
var webunpack = require("webunpack.js"); 

var results = webunpack.unpackFile("./tests/testhandlebarsvuln/dist/main.js", "./dbs/signaturesdbfiltered.json");

console.dir(results);
```
The output should be the list of vulnerable modules identified in the packed file:

```javascript
[ { name: 'handlebars',
    version: '4.3.2',
    vulnerable: 'https://npmjs.com/advisories/1325' },
  { name: 'handlebars',
    version: '4.4.1',
    vulnerable: 'https://npmjs.com/advisories/1325' },
  { name: 'handlebars',
    version: '4.2.2',
    vulnerable: 'https://npmjs.com/advisories/1164' } ]
```

## API documentation
***
- webunpack.unpackFile(packedfile, signaturesdb, mostrelevantmodule = false);  
- webunpack.unpackString(packedstring, signaturesdb, mostrelevantmodule = false);  
the last parameter if set to true imply that only the most relevant vulnerable module will be displayed.
- webunpack.fetchVulnerabilities();  
- webunpack.createSignatures(vulnerablemodulesfile, signaturesdb);  
- webunpack.updateSignatures(vulnerablemodulesfile, signaturesdb);  
- webunpack.signaturesdbFilter(signaturesdb);  
***

## How it works?
For the moment the only source of npm vulnerable modules is https://npmjs.com/advisories/  
For each vulnerable version of a module, createSignatures() method will compute a hash of each function.  
Then unpackFile() method will compute the hash of each of the function inside a packed file and compare it to the ones in a signatures database.  

## Faq
[Here](./docs/FAQ.md)
