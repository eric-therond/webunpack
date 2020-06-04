const signaturesmodule = require('./signatures.js');
const execSync = require('child_process').execSync;
const fetch = require('node-fetch');
const fs = require('fs');

var DIR_TMPWEBPACK = __dirname+"/../tmpwebpack/";
var DIR_DATABASES = __dirname+"/../dbs/";
var signatures = [];
var DEBUG = true;

function compareVersion(vers1, vers2) {
    
    if(vers1 === null || vers2 === null) {
        return 2;
    }
    
    var v1 = vers1.split(".");
    var v2 = vers2.split(".");
    
    v1[0] = parseInt(v1[0], 10);
    v1[1] = parseInt(v1[1], 10);
    v1[2] = parseInt(v1[2], 10);
    v2[0] = parseInt(v2[0], 10);
    v2[1] = parseInt(v2[1], 10);
    v2[2] = parseInt(v2[2], 10);
    
    if(v1[0] < v2[0]) {
        return -1; // vers1 infstrict vers2
    }
    else if(v1[0] === v2[0]) {
        if(v1[1] < v2[1]) {
            return -1; // vers1 infstrict vers2
        }
        else if(v1[1] === v2[1]) {
            if(v1[2] < v2[2]) {
                return -1; // vers1 infstrict vers2
            }
            else if(v1[2] === v2[2]) {
                return 0; // vers1 equal vers2
            }
        }
    }
    
    return 1; // vers2 supstrict vers1
}

function isVulnerableVersion(version, vulnerableversions) {
    
    var ret = false;
    vulnerableversions.forEach(function(cond) {
        if((compareVersion(version, cond["supequal"]) === 0 || cond["supequal"] === null)
            && (compareVersion(version, cond["infequal"]) === 0 || cond["infequal"] === null)
                && (compareVersion(version, cond["infstrict"]) === -1 || cond["infstrict"] === null) 
                    && (compareVersion(version, cond["supstrict"]) === 1 || cond["supstrict"] === null)) {
            ret = true;
            return;
        }
    });
    
    return ret;
}

function getSignature(pkgname, version, vulnerableversions) {
    
    console.log("getSignature of module '"+pkgname+"' version '"+version+"'");
    
    if(generateWebPack(pkgname, version)) {
        var vulntxt = false;
        if(isVulnerableVersion(version, vulnerableversions)) {
            vulntxt = vulnerableversions["url"];
        }
        
        if (fs.existsSync(DIR_TMPWEBPACK+"./dist/main.js")) {
            
            var objmodule = {
                "name": pkgname,
                "version": version,
                "signature": signaturesmodule.computeSignature(fs.readFileSync(DIR_TMPWEBPACK+"./dist/main.js").toString()),
                "vulnerable": vulntxt
            }
            
            console.debug(" signature pushed");
            signatures.push(objmodule);  
        }
    }    
}

function getVersionsFromDb(pkgname) {
    
    var versions = [];
    
    signatures.forEach(function(module) {
        if(module["name"] === pkgname) {
            versions.push(module["version"]);
        }
    });
    
    return versions;
}

function forEachVersion(pkgname, versions, vulnerableversions) {
  
    var testedversions = getVersionsFromDb(pkgname);
    
    var step = 1;
    if(versions.length > 20 && versions.length <= 100) {
        step = 5;
    }
    else if(versions.length > 100) {
        step = parseInt(versions.length / 10);
    }
    
    for(var i = 0; i < versions.length; i+=step) {
        var version = versions[i];
        
        if(testedversions.indexOf(version) === -1) {
            testedversions.push(version);
            getSignature(pkgname, version, vulnerableversions);
        }
    }
    
    for(var i = 0; i < vulnerableversions.length; i ++) {
        
        var limitsvulnsversions = [];
        limitsvulnsversions.push(vulnerableversions[i]["supequal"]);
        limitsvulnsversions.push(vulnerableversions[i]["infequal"]);
        limitsvulnsversions.push(vulnerableversions[i]["infstrict"]);
        limitsvulnsversions.push(vulnerableversions[i]["supstrict"]);
        
        for(var j = 0; j < limitsvulnsversions.length; j ++) {
            if(limitsvulnsversions[j] !== null) {
                var idx = versions.indexOf(limitsvulnsversions[j]);
                
                if(idx != -1) {
                    
                    if(testedversions.indexOf(limitsvulnsversions[j]) === -1) {
                        getSignature(pkgname, limitsvulnsversions[j], vulnerableversions);
                    }
                    
                    if((idx - 1) >= 0) {
                        if(testedversions.indexOf(versions[idx - 1]) === -1) {
                            getSignature(pkgname, versions[idx - 1], vulnerableversions);
                        }
                    }
                
                    if((idx + 1) < versions.length) {
                        if(testedversions.indexOf(versions[idx + 1]) === -1) {
                            getSignature(pkgname, versions[idx + 1], vulnerableversions);
                        }
                    }
                }
            }
        }
    }
}

function installWebPack(tmpwebpack) {
    
    try {
        execSync('cd '+tmpwebpack+';rm -rf node_modules/ 2>/dev/null;rm -rf dist/ 2>/dev/null;mkdir dist;touch dist/.gitkeep');
        execSync('cd '+tmpwebpack+';npm install --prefix '+tmpwebpack+' --save -f --prefer-offline --no-audit 2>/dev/null');
        execSync('cd '+tmpwebpack+';npx webpack --config webpack.config.js 2>/dev/null');
    }
    catch(e) {
        //console.log("error = "+e);
        return false;
    }
    
    return true;
}

function generateWebPack(pkgname, version) {
    
    let content1 = { 
        "name": "autogenerate-webunpack",
        "version": "0.0.1",
        "private": true,
        "author": "",
        "license": "MIT",
        "dependencies": {
            [pkgname]: version
        }
    }; 
    
    let content2 = {
        "name": "autogenerate-webunpack",
        "version": "0.0.1",
        "lockfileVersion": 1,
        "requires": true,
        "dependencies": {
            [pkgname]: {
                "version": version,
                "requires": false,
                "dependencies": false
            }
        }
    }; 

    
    fs.writeFileSync(DIR_TMPWEBPACK+'./package.json', JSON.stringify(content1));
    fs.writeFileSync(DIR_TMPWEBPACK+'./package-lock.json', JSON.stringify(content2));
    fs.writeFileSync(DIR_TMPWEBPACK+'./src/index.js', "var tmp = require('"+pkgname+"');");
        
    return installWebPack(DIR_TMPWEBPACK);
}

function printTmpDirDoesntExist() {
    console.error("---------\nwebunpack\n---------\n");
    console.error(__dirname+"/tmpwebpack/ dir doesn't exist or read/write permission not granted\n\n");
}

function computeVersions(versions) {
    var array = versions.split("||");
    
    var i = 0;
    var conds = [];
    array.forEach(function(element) {
        
        conds[i] = [];
        conds[i]["infstrict"] = null;
        conds[i]["infequal"] = null;
        conds[i]["supstrict"] = null;
        conds[i]["supequal"] = null;
        
        
        var infstrict = element.match(/<\s*(\d+\.\d+\.\d+)/);
        if(infstrict !== null) {
            conds[i]["infstrict"] = infstrict[1];
        }
        
        var infequal = element.match(/<=\s*(\d+\.\d+\.\d+)/);
        if(infequal !== null) {
            conds[i]["infequal"] = infequal[1];
        }
        
        var supstrict = element.match(/>\s*(\d+\.\d+\.\d+)/);
        if(supstrict !== null) {
            conds[i]["supstrict"] = supstrict[1];
        }
        
        var supequal = element.match(/>=\s*(\d+\.\d+\.\d+)/);
        if(supequal !== null) {
            conds[i]["supequal"] = supequal[1];
        }
    });
    
    return conds;
}

function readBlacklistedModules() {
    
    var modulesblacklisted= fs.readFileSync("blacklistedmodules.txt").toString().split("\n");
    modulesblacklisted.concat([]);
        
    modulesblacklisted = modulesblacklisted.map(module =>  module.trim());
        
    return modulesblacklisted;
}

function modulesFilter(modules) {
    
    var newmodules = [];
    
    modules.forEach(function(module1) {
        var newmodule = {
            "name": module1["name"],
            "version":  module1["version"],
            "signature": [],
            "vulnerable": module1["vulnerable"]
        };
    
        module1["signature"].forEach(function(signature1) {
            var nbmatches = 0;
            modules.forEach(function(module2) {
                module2["signature"].forEach(function(signature2) {
                    if(signature1 === signature2 && module2["name"] !== module1["name"]) {
                        nbmatches ++;
                    }
                });
            });
            
            if(nbmatches < 3) {
                newmodule["signature"].push(signature1);
            }
        });
        
        newmodules.push(newmodule);
    });  
                
    return newmodules;
}

function cveIsPresent(cve, modules) {
  for(var i = 0; i < modules.length; i ++) {
    if(modules[i]["vulnerable"] === cve) {
      return true;
    }
  }
  
  return false;
}

function signaturesdbFilter(signaturesdb) {
    
    try {
        if (!fs.existsSync(signaturesdb)) {
            console.error("file "+signaturesdb+" not found");
        }
        else {
            var modules = JSON.parse(fs.readFileSync(signaturesdb).toString());
            
            fs.writeFileSync(signaturesdb, JSON.stringify(modulesFilter(modules)));
        } 
    } catch(err) {
        console.error(err)
    }
}

function updateSignatures(file, signaturedb) {
    try {
        
        if (!fs.existsSync("blacklistedmodules.txt")) {
            console.error("file blacklistedmodules.txt not found");
        }
        else {
            var modulesblacklisted= readBlacklistedModules();
            
            if (!fs.existsSync(file)) {
                console.error("file "+file+" not found");
            }
            else if (!fs.existsSync(file)) {
                console.error("file "+signaturedb+" not found");
            }
            else {
                signatures = JSON.parse(fs.readFileSync(signaturedb).toString());
                
                var array = fs.readFileSync(file).toString().split("\n");
                var length = array.length;
                for(i in array) {
                    var newarray = array[i].split(";");
                    if(typeof newarray[1] !== 'undefined' && typeof newarray[5] !== 'undefined') {
                        var pkgname = newarray[1];
                        var cve = newarray[5];
                        
                        if(modulesblacklisted.includes(pkgname)) {
                            console.log("module "+pkgname+" is blacklisted");
                        }
                        else if(cveIsPresent(cve, signatures)) {
                            console.log("cve "+cve+" already in database");
                        }
                        else {
                            var vulnerableversions = computeVersions(newarray[2]);
                            vulnerableversions["url"] = newarray[5];
                            try {
                                var versions = JSON.parse(execSync('npm view '+pkgname+' versions --json 2>/dev/null').toString());
                                
                                console.log("getSignature of module '"+pkgname+"' ("+i+"/"+length+")");
                                forEachVersion(pkgname, versions, vulnerableversions);
                                
                            } catch(err) {
                                console.error(err)
                            }
                        }
                    }
                }
                
                console.debug("database "+signaturedb+" updated");
                
                fs.writeFileSync(signaturedb, JSON.stringify(modulesFilter(signatures)));
            }
        }
    } catch(err) {
        console.error(err)
    }
}

function createSignatures(file, signaturedb) {
    try {
        
        if (!fs.existsSync("blacklistedmodules.txt")) {
            console.error("file blacklistedmodules.txt not found");
        }
        else {
            var modulesblacklisted = readBlacklistedModules();
            
            if (!fs.existsSync(file)) {
                console.error("file "+file+" not found");
            }
            else {
                var array = fs.readFileSync(file).toString().split("\n");
                var length = array.length;
                for(i in array) {
                    var newarray = array[i].split(";");
                    if(typeof newarray[1] !== 'undefined') {
                        var pkgname = newarray[1];
                        
                        if(modulesblacklisted.includes(pkgname)) {
                            console.log("module "+pkgname+" is blacklisted");
                        }
                        else {
                            var vulnerableversions = computeVersions(newarray[2]);
                            vulnerableversions["url"] = newarray[5];
                            
                            try {
                                var versions = JSON.parse(execSync('npm view '+pkgname+' versions --json 2>/dev/null').toString());
                                console.log("getSignature of module '"+pkgname+"' ("+i+"/"+length+")");
                                forEachVersion(pkgname, versions, vulnerableversions);
                            } catch(err) {
                                console.error(err)
                            }
                        }
                    }
                }

                fs.writeFileSync(signaturedb, JSON.stringify(modulesFilter(signatures)));
                
                return true;
            }
        }
    } catch(err) {
        console.error(err)
    }
    
    return false;
}

function printVulnerabilities(results) {
    if(typeof results["advisoriesData"] !== 'undefined' && typeof results["advisoriesData"]["objects"] !== 'undefined') {
            
        var vulns = results["advisoriesData"]["objects"];
                
        vulns.forEach(function(element) {
            console.log(element["id"]+";"+element["module_name"]+";"+element["vulnerable_versions"]+";"+element["patched_versions"]+";"+element["severity"]+";"+element["url"]);
        });
    }
}

function fetchOneVulnerabilitiesPage(results) {
    var maxperrequest = 200;
    
    if(typeof results["advisoriesData"] !== 'undefined' && typeof results["advisoriesData"]["total"] !== 'undefined') {
        
        var page = Math.ceil(results["advisoriesData"]["total"] / maxperrequest);
        
        for(var i = 0; i < page; i ++) {
            fetch('https://www.npmjs.com/advisories?page='+i+'&perPage='+maxperrequest, {
                method: "GET",
                headers: {
                    "Host": "www.npmjs.com",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
                    "Accept": "*/*",
                    "x-requested-with": "XMLHttpRequest",
                    "x-spiferack": "1"
                }})
            .then(res => res.json())
            .then(json => printVulnerabilities(json));
        }
    }
}

function fetchVulnerabilities() {
    fetch('https://www.npmjs.com/advisories?page=0&perPage=1', {
        method: "GET",
        headers: {
            "Host": "www.npmjs.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Accept": "*/*",
            "x-requested-with": "XMLHttpRequest",
            "x-spiferack": "1"
        }})
    .then(res => res.json())
    .then(json => fetchOneVulnerabilitiesPage(json));
}

function getVulnerableModules(packeddata, signaturesfile) {
    
    var modules = [];
    
    if(!fs.existsSync(signaturesfile)) {
        console.error("file "+signaturesfile+" not found");
    }
    else
    {
        var signaturesdb = null;
        
        try {
            signaturesdb = JSON.parse(fs.readFileSync(signaturesfile).toString());
        }
        catch(e) {
            console.error("file "+signaturesfile+" is not a JSON file");
        }
        
        var ret = signaturesmodule.compareSignature(packeddata, signaturesdb);
       
        if(ret.found) {
            for(var i = 0; i < ret.module.length; i ++) {
                var percentSimilitudes = (ret.module[i]["verify"] / ret.module[i]["signature"].length) * 100;
                if(ret.module[i].vulnerable !== false && percentSimilitudes > 80) {
                    modules.push(ret.module[i]);
                }
            }
        }
    }
     
    return modules;
}


function getMostSimilitudesVulnerableModule(modules) {
    
    var highestoccur = 0;
    var bestmodule = {
        "name": null,
        "version": null,
        "signature": null,
        "vulnerable": false
    };
        
    modules.forEach(function(module1) {
        if(module1["verify"] >= highestoccur) {
            highestoccur = module1["verify"];
            bestmodule = module1;
        }
    });
    
    return bestmodule;
}

function unpackString(packeddata, signaturedb = DIR_DATABASES+"/signaturesdbfiltered.json", onlythemostsimilitudesmodule = false) {
    
    var modules = getVulnerableModules(packeddata, signaturedb);
        
    if(onlythemostsimilitudesmodule) {
        return getMostSimilitudesVulnerableModule(modules);
    }
    
    var results = [];
    
    modules.forEach(function(module1) {
        var obj = {
            "name": module1["name"],
            "version": module1["version"],
            "vulnerable": module1["vulnerable"]
        };
        
        results.push(obj);
    });
    
    return results;
}

function unpackFile(packedfile, signaturedb = DIR_DATABASES+"/signaturesdbfiltered.json", onlythemostsimilitudesmodule = false) {
    
    if (!fs.existsSync(packedfile)) {
        console.error("file "+packedfile+" not found");
        return [];
    }
    
    return unpackString(fs.readFileSync(packedfile).toString(), signaturedb, onlythemostsimilitudesmodule);
}

module.exports.fetchVulnerabilities = fetchVulnerabilities;
module.exports.updateSignatures = updateSignatures;
module.exports.signaturesdbFilter = signaturesdbFilter;
module.exports.createSignatures = createSignatures;
module.exports.unpackFile = unpackFile;
module.exports.unpackString = unpackString;
module.exports.getMostSimilitudesVulnerableModule = getMostSimilitudesVulnerableModule;
module.exports.generateWebPack = generateWebPack;
module.exports.installWebPack = installWebPack;



