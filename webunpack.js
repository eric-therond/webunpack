const lib = require('./lib/index.js');
const fs = require('fs');

var DIR_TMPWEBPACK = __dirname+"/tmpwebpack/";

function printCmdUsage() {
    console.error("---------\nwebunpack\n---------\n");
    console.error("command: node webunpack.js option [file1] [file2]\n\t");
    console.error("option:");
    console.error(" - getvulns: fetch vulnerabilities from npmjs.com and print the result to console");
    console.error(" - createdb: create signatures database (file2) from list of vulnerable modules in file1");
    console.error(" - filterdb: filter signatures database (file1) to remove duplicate signatures");
    console.error(" - updatedb: update signatures database (file2) from list of vulnerable modules in file1");
    console.error(" - unpack: analyze packed file2 against signatures database (file1)\n\n");
}

if(!fs.existsSync(DIR_TMPWEBPACK)) {
    printTmpDirDoesntExist();
}

try {
    fs.accessSync(DIR_TMPWEBPACK, fs.constants.W_OK | fs.constants.R_OK);
}
catch (e) {
    printTmpDirDoesntExist();
}

if(process.argv.length > 2) {
    
    switch(process.argv[2]) {
        case "getvulns":
            lib.fetchVulnerabilities();
            break;
            
        case "createdb":
            if(process.argv.length > 4) {
                lib.createSignatures(process.argv[3], process.argv[4]);
            }
            else {
                printCmdUsage();
            }
            break;
            
        case "updatedb":
            if(process.argv.length > 4) {
                lib.updateSignatures(process.argv[3], process.argv[4]);
            }
            else {
                printCmdUsage();
            }
            break;
            
        case "filterdb":
            if(process.argv.length > 3) {
                lib.signaturesdbFilter(process.argv[3]);
            }
            else {
                printCmdUsage();
            }
            break;
            
        case "unpack":
            if(process.argv.length > 4) {
                console.dir(lib.unpackFile(process.argv[4], process.argv[3]), {'maxArrayLength': null});
            }
            else {
                printCmdUsage();
            }
            break;
            
        default:
            printCmdUsage();
    }    
}
else {
    printCmdUsage();
}


