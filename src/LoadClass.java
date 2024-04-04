class LoadClass {
    public static Object getInstanceByConfig(String a) throws Exception{
        a=getNameByConfig(a);
        //try{
        //    return getClassByName(a).newInstance();
        //}catch(Exception e){
        //    return getForce(a, e);
        //}
        return getClassByName(a).newInstance();
    }
    public static Object getInstanceByName(String a) throws Exception{
        //try{
        //    return getClassByName(a).newInstance();
        //}catch(Exception e){
        //    return getForce(a, e);
        //}
        return getForce(a, new Exception());
    }
    public static Class getClassByConfig(String a) throws Exception{
        return getClassByName(getNameByConfig(a));
    }
    public static Class getClassByName(String a) throws Exception{
        //DebugPrint("Class Load: "+ a);
        return Class.forName(a);
    }
    public static String getNameByConfig(String a) {
        String b=(String)config.get(a);
        if ( b == null )
            DebugPrint("getNameByConfig Fail: : "+ a);
        return b;
    }    
    public static void DebugPrintException(String a) {
        DebugPrint("       " + a);        
    }
    public static void DebugPrint(String a) {
        System.out.println(a);        
    }
    // Usage in GraalVM
    public static Object getForce(String key, Exception e) throws Exception{
        //DebugPrint("Loading Force... " + key);
        //if ( key.equals("KeyExchangeDHGEX") ) return (Object)(new KeyExchangeDHGEX());
        //if ( key.equals("KeyExchangeDHG1") ) return (Object)(new KeyExchangeDHG1());
        //if ( key.equals("KeyExchangeDHG14") ) return (Object)(new KeyExchangeDHG14());
        //if ( key.equals("KeyExchangeDHGEX256") ) return (Object)(new KeyExchangeDHGEX256());
        //if ( key.equals("SignatureECDSA256") ) return (Object)(new SignatureECDSA256());
        //if ( key.equals("SignatureECDSA384") ) return (Object)(new SignatureECDSA384());
        //if ( key.equals("SignatureECDSA521") ) return (Object)(new SignatureECDSA521());
        //if ( key.equals("KeyExchangeDHEC256") ) return (Object)(new KeyExchangeDHEC256());
        //if ( key.equals("KeyExchangeDHEC384") ) return (Object)(new KeyExchangeDHEC384());
        if ( key.equals("KeyExchangeDHEC521") ) return (Object)(new KeyExchangeDHEC521());
        if ( key.equals("KeyExchangeECDHN") ) return (Object)(new KeyExchangeECDHN());
        //if ( key.equals("KeyExchangeDH") ) return (Object)(new KeyExchangeDH());
        //if ( key.equals("CipherTripleDESCBC") ) return (Object)(new CipherTripleDESCBC());
        //if ( key.equals("BlowfishCBC") ) return (Object)(new BlowfishCBC());
        if ( key.equals("HMACSHA1") ) return (Object)(new HMACSHA1());
        //if ( key.equals("HMACSHA196") ) return (Object)(new HMACSHA196());
        //if ( key.equals("HMACSHA256") ) return (Object)(new HMACSHA256());
        //if ( key.equals("HMACMD5") ) return (Object)(new HMACMD5());
        //if ( key.equals("HMACMD596") ) return (Object)(new HMACMD596());
        //if ( key.equals("HASHSHA1") ) return (Object)(new HASHSHA1());
        //if ( key.equals("HASHSHA256") ) return (Object)(new HASHSHA256());
        //if ( key.equals("HASHSHA384") ) return (Object)(new HASHSHA384());
        if ( key.equals("HASHSHA512") ) return (Object)(new HASHSHA512());
        //if ( key.equals("HASHMD5") ) return (Object)(new HASHMD5());
        //if ( key.equals("SignatureDSA") ) return (Object)(new SignatureDSA());
        if ( key.equals("SignatureRSA") ) return (Object)(new SignatureRSA());
        //if ( key.equals("KeyPairGenDSA") ) return (Object)(new KeyPairGenDSA());
        //if ( key.equals("KeyPairGenRSA") ) return (Object)(new KeyPairGenRSA());
        //if ( key.equals("KeyPairGenECDSA") ) return (Object)(new KeyPairGenECDSA());
        if ( key.equals("Random") ) return (Object)(new Random());        
        //if ( key.equals("CipherAES128CBC") ) return (Object)(new CipherAES128CBC());
        //if ( key.equals("CipherAES192CBC") ) return (Object)(new CipherAES192CBC());
        //if ( key.equals("CipherAES256CBC") ) return (Object)(new CipherAES256CBC());
        //if ( key.equals("CipherAES128CTR") ) return (Object)(new CipherAES128CTR());
        //if ( key.equals("CipherAES192CTR") ) return (Object)(new CipherAES192CTR());
        if ( key.equals("CipherAES256CTR") ) return (Object)(new CipherAES256CTR());
        //if ( key.equals("CipherTripleDESCTR") ) return (Object)(new CipherTripleDESCTR());
        //if ( key.equals("CipherARCFOUR") ) return (Object)(new CipherARCFOUR());
        //if ( key.equals("CipherARCFOUR128") ) return (Object)(new CipherARCFOUR128());
        //if ( key.equals("CipherARCFOUR256") ) return (Object)(new CipherARCFOUR256());
        if ( key.equals("UserAuthNone") ) return (Object)(new UserAuthNone());
        if ( key.equals("UserAuthPassword") ) return (Object)(new UserAuthPassword());
        //if ( key.equals("UserAuthKeyboardInteractive") ) return (Object)(new UserAuthKeyboardInteractive());
        //if ( key.equals("UserAuthPublicKey") ) return (Object)(new UserAuthPublicKey());
        //if ( key.equals("UserAuthGSSAPIWithMIC") ) return (Object)(new UserAuthGSSAPIWithMIC());
        //if ( key.equals("GSSContextKrb5") ) return (Object)(new GSSContextKrb5());
        //if ( key.equals("Compression") ) return (Object)(new Compression());
        //if ( key.equals("Compression") ) return (Object)(new Compression());
        //if ( key.equals("PBKDF") ) return (Object)(new PBKDF());  
      
        DebugPrint("FailLoadClass !! " + key);
        throw e;
    }
 
    static java.util.Hashtable config=new java.util.Hashtable();
    static{
        //config.put("diffie-hellman-group-exchange-sha1","KeyExchangeDHGEX");
        //config.put("diffie-hellman-group1-sha1","KeyExchangeDHG1");
        //config.put("diffie-hellman-group14-sha1","KeyExchangeDHG14");
        //config.put("diffie-hellman-group-exchange-sha256","KeyExchangeDHGEX256");
        //config.put("ecdsa-sha2-nistp256","SignatureECDSA256");
        //config.put("ecdsa-sha2-nistp384","SignatureECDSA384");
        //config.put("ecdsa-sha2-nistp521","SignatureECDSA521");
        //config.put("ecdh-sha2-nistp256","KeyExchangeDHEC256");
        //config.put("ecdh-sha2-nistp384","KeyExchangeDHEC384");
        config.put("ecdh-sha2-nistp521","KeyExchangeDHEC521");        
        config.put("ecdh-sha2-nistp","KeyExchangeECDHN");
        //config.put("dh","KeyExchangeDH");
        //config.put("3des-cbc","CipherTripleDESCBC");
        //config.put("blowfish-cbc","BlowfishCBC");
        config.put("hmac-sha1","HMACSHA1");
        //config.put("hmac-sha1-96","HMACSHA196");
        //config.put("hmac-sha2-256","HMACSHA256");
        //config.put("hmac-md5","HMACMD5");
        //config.put("hmac-md5-96","HMACMD596");
        //config.put("sha-1","HASHSHA1");
        //config.put("sha-256","HASHSHA256");
        //config.put("sha-384","HASHSHA384");
        config.put("sha-512","HASHSHA512");
        //config.put("md5","HASHMD5");
        //config.put("signature.dss","SignatureDSA");
        config.put("signature.rsa","SignatureRSA");
        //config.put("keypairgen.dsa","KeyPairGenDSA");
        //config.put("keypairgen.rsa","KeyPairGenRSA");
        //config.put("keypairgen.ecdsa","KeyPairGenECDSA");
        config.put("random","Random");
        //config.put("none","CipherNone");
        //config.put("aes128-cbc","CipherAES128CBC");
        //config.put("aes192-cbc","CipherAES192CBC");
        //config.put("aes256-cbc","CipherAES256CBC");
        //config.put("aes128-ctr","CipherAES128CTR");
        //config.put("aes192-ctr","CipherAES192CTR");
        config.put("aes256-ctr","CipherAES256CTR");
        //config.put("3des-ctr","CipherTripleDESCTR");
        //config.put("arcfour","CipherARCFOUR");
        //config.put("arcfour128","CipherARCFOUR128");
        //config.put("arcfour256","CipherARCFOUR256");
        config.put("userauth.none","UserAuthNone");
        config.put("userauth.password","UserAuthPassword");
        //config.put("userauth.keyboard-interactive","UserAuthKeyboardInteractive");
        //config.put("userauth.publickey","UserAuthPublicKey");
        //config.put("userauth.gssapi-with-mic","UserAuthGSSAPIWithMIC");
        //config.put("gssapi-with-mic.krb5","GSSContextKrb5");
        //config.put("zlib","Compression");
        //config.put("zlib@openssh.com","Compression");
        //config.put("pbkdf","PBKDF");
        
        config.put("kex","ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1");
        config.put("server_host_key","ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");
        config.put("cipher.s2c","aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-ctr,aes192-cbc,aes256-ctr,aes256-cbc");
        config.put("cipher.c2s","aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-ctr,aes192-cbc,aes256-ctr,aes256-cbc");
        config.put("mac.s2c","hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96");
        config.put("mac.c2s","hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96");
        config.put("compression.s2c","none");
        config.put("compression.c2s","none");
        config.put("lang.s2c","");
        config.put("lang.c2s","");
        config.put("compression_level","6");
        config.put("StrictHostKeyChecking","ask");
        config.put("HashKnownHosts","no");
        config.put("PreferredAuthentications","gssapi-with-mic,publickey,keyboard-interactive,password");
        config.put("CheckCiphers","aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-ctr,arcfour,arcfour128,arcfour256");
        config.put("CheckKexes","diffie-hellman-group14-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521");
        config.put("CheckSignatures","ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");
        config.put("MaxAuthTries","6");
        config.put("ClearAllForwardings","no");
    }    
}
