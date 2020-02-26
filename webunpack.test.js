const lib = require('./lib/index.js');
const signaturesmodule = require('./lib/signatures.js');
const execSync = require('child_process').execSync;
const fs = require('fs');

const DIR_TMPWEBPACK_TEST = __dirname+"/tests";


test('handlebars vuln', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testhandlebarsvuln";
    
    if(lib.installWebPack(DIR_MODULE)) {
        var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdbfiltered.json", true);

        expect(ret.name).toBe("handlebars");
        expect(ret.version).toBe("4.3.2");
        expect(ret.version).not.toBe(false);
    }
}); 
/*
test('validator react largedb', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testlargedbreactvuln";
    
    if(lib.installWebPack(DIR_MODULE)) {
        var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdb.json", true);

        expect(ret.name).toBe("react");
        expect(ret.version).toBe("0.5.0");
        expect(ret.version).not.toBe(false);
    }
}); 

test('validator vuln', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testvalidatorvuln";
    
    if(lib.installWebPack(DIR_MODULE)) {
        var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdb.json", true);

        expect(ret.name).toBe("validator");
        expect(ret.version).toBe("1.0.0");
        expect(ret.version).not.toBe(false);
    }
}); 

test('validator nonvuln', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testvalidatornonvuln";
    
    if(lib.installWebPack(DIR_MODULE)) {
        var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdb.json", true);

        expect(ret.name).toBe(null);
        expect(ret.version).toBe(null);
    }
}); 

test('lodash vuln', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testlodashvuln";
    
    if(lib.installWebPack(DIR_MODULE)) {
        var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdb.json", true);

        expect(ret.name).toBe(null);
        expect(ret.version).toBe(null);
    }
}); 

test('lodash nonvuln', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testlodashnonvuln";
    
    if(lib.installWebPack(DIR_MODULE)) {
        var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdb.json", true);

        expect(ret.name).toBe(null);
        expect(ret.version).toBe(null);
    }
}); 

test('lodash vuln complete fictif test', () => {
    var DIR_MODULE = DIR_TMPWEBPACK_TEST+"/testcompletelodashvuln";
    
    if(lib.createSignatures(DIR_MODULE+"/fakevulnlodash.txt", DIR_MODULE+"/signaturesdb.json")) {
        if(lib.installWebPack(DIR_MODULE)) {
            var ret = lib.unpackFile(DIR_MODULE+"/dist/main.js", DIR_MODULE+"/signaturesdb.json", true);

            console.dir(ret);
            expect(ret.name).toBe("lodash");
            expect(ret.version).toBe("4.0.0");
        }
    }
}); 

*/
