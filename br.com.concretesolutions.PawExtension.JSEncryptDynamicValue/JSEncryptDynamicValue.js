
(function() {
    navigator = function () {
        
    };
    
    alert = function (text) {
        console.log(text);
    }
    
    require("vendor/pidcrypt_c.js");
    require("vendor/pidcrypt_util_c.js");
    require("vendor/libs/asn1_c.js");
    require("vendor/libs/jsbn_c.js");
    require("vendor/libs/rng_c.js");
    require("vendor/libs/prng4_c.js");
    require("vendor/libs/rsa_c.js");
    require("extra.js");
    
    
    var JSEncryptDynamicValue;
    JSEncryptDynamicValue = function() {
        this.evaluate = function(context) {
            if (this.publickey === "" && this.text === "")
                return ["Provide both public key and text to encrypt"];
            else if (this.publickey === "")
                return ["Provide public key"];
            else if (this.text === "")
                return ["Provide text to encrypt"];
            else {
                params = certParser(this.publickey);
                if(params.b64){
                    var key = pidCryptUtil.decodeBase64(params.b64);
                    //new RSA instance
                    var rsa = new pidCrypt.RSA();
                    //RSA encryption
                    //ASN1 parsing
                    var asn = pidCrypt.ASN1.decode(pidCryptUtil.toByteArray(key));
                    var tree = asn.toHexTree();
                    //setting the public key for encryption
                    rsa.setPublicKeyFromASN(tree);
                    return rsa.encrypt(this.text);
                } else {
                    console.log("Invalid key!");
                    return ["Invalid public key"];
                }
            }
        };
        this.title = function() {
            return "RSAEncrypt";
        };
    };

    JSEncryptDynamicValue.identifier = "br.com.concretesolutions.PawExtension.JSEncryptDynamicValue";

    JSEncryptDynamicValue.title = "JSEncrypt Dynamic Value";

    JSEncryptDynamicValue.inputs = [
      DynamicValueInput("publickey", "Public Key", "String"),
      DynamicValueInput("text", "Text to Encrypt", "String")
    ];
    registerDynamicValueClass(JSEncryptDynamicValue); 
}).call(this);
