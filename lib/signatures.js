var crypto = require("crypto");
const recast = require('recast');
const { Parser } = require("acorn");
const fs = require('fs');

const SIZE_LIMIT = 30;

function computeSignature(unpackeddata) {
    
    var i = 0;
    var functionSizes = [];
    var functionHashs = [];
    var tmpSigns = [];
    
    try {
        const ast = Parser.parse(unpackeddata);
            
        recast.visit(ast, {
                
            visitFunctionExpression(path) {
                var newPath = path.get('body');
                var currentNodeTypes = "";
                var currentSize = 0;
                    
                // for each node
                recast.visit(newPath, {
                    visitNode(newPath) {
                        currentNodeTypes += newPath.node.type;
                        currentSize ++;
                        this.traverse(newPath);
                    }
                });
                    
                if(currentSize > SIZE_LIMIT) {
                    var obj = {
                        size: currentSize,
                        signature: crypto.createHash("sha256").update(currentNodeTypes, 'utf-8').digest("hex")
                    };
                    tmpSigns.push(obj);
                }
                return false;
            },
                
            visitFunctionDeclaration(path) {
                var newPath = path.get('body');
                var currentNodeTypes = "";
                var currentSize = 0;
                    
                // for each node
                recast.visit(newPath, {
                    visitNode(newPath) {
                        currentNodeTypes += newPath.node.type;
                        currentSize ++;
                        this.traverse(newPath);
                    }
                });
                    
                if(currentSize > SIZE_LIMIT) {
                    var obj = {
                        size: currentSize,
                        signature: crypto.createHash("sha256").update(currentNodeTypes, 'utf-8').digest("hex")
                    };
                        
                    tmpSigns.push(obj);
                }
                return false;
            }
        });
            
        tmpSigns.sort((a, b) => (a.size > b.size) ? -1 : 1);
    } 
    catch(err) {
        console.error(err)
    }
        
    var rettmpSigns = [];
    tmpSigns.forEach(function(element) {
        rettmpSigns.push(element.signature);
    });
        
    return rettmpSigns;
}

function compareSignature(packeddata, signaturesdb) {

    var ret = {
        "found": false,
        "module": []
    };   
    
    if(Array.isArray(signaturesdb)) {
        try {
            const ast = Parser.parse(packeddata);
        
            recast.visit(ast, {
                
                visitFunctionExpression(path) {
                    var currentNodeTypes = "";
                    var newPath = path.get('body');
                        
                    // for each node
                    recast.visit(newPath, {
                        visitNode(newPath) {
                            currentNodeTypes += newPath.node.type;
                            this.traverse(newPath);
                        }
                    });
                            
                    // end of function declaration
                    var tmpsignature = crypto.createHash("sha256").update(currentNodeTypes, 'utf-8').digest("hex");      
                    for(var j = 0; j < signaturesdb.length; j ++) {
                        for(var i = 0; i < signaturesdb[j]["signature"].length; i ++) {
                            if(tmpsignature === signaturesdb[j]["signature"][i]) {
                                if(typeof signaturesdb[j]["verify"] === 'undefined') {
                                    signaturesdb[j]["verify"] = 0;
                                }
                                
                                signaturesdb[j]["verify"] ++;
                                break;
                            }
                        }
                    }
                    
                    return false;
                },
                
                visitFunctionDeclaration(path) {
                        
                    var currentNodeTypes = "";
                    var newPath = path.get('body');

                    // for each node
                    recast.visit(newPath, {
                        visitNode(newPath) {
                            currentNodeTypes += newPath.node.type;
                            this.traverse(newPath);
                        }
                    });
                            
                    // end of function declaration
                    var tmpsignature = crypto.createHash("sha256").update(currentNodeTypes, 'utf-8').digest("hex");
                            
                    for(var j = 0; j < signaturesdb.length; j ++) {
                        for(var i = 0; i < signaturesdb[j]["signature"].length; i ++) {
                            if(tmpsignature === signaturesdb[j]["signature"][i]) {
                                
                                if(typeof signaturesdb[j]["verify"] === 'undefined') {
                                    signaturesdb[j]["verify"] = 0;
                                }
                                
                                signaturesdb[j]["verify"] ++;
                                break;
                            }
                        }
                    }
                        
                    return false;
                }
            });
            
            for(var i = 0; i < signaturesdb.length; i ++) {
                if(typeof signaturesdb[i]["verify"] !== 'undefined') {
                    ret.found = true;
                    ret.module.push(signaturesdb[i]);
                }
            }
            
            
        } catch(err) {
            console.error(err)
        }
    }
    
    return ret;
}

module.exports.computeSignature = computeSignature;
module.exports.compareSignature = compareSignature;
