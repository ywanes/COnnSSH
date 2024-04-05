class ALoadClass {
    public static Object getInstanceByConfig(String a) throws Exception{
        a=getNameByConfig(a);
        return getClassByName(a).newInstance();
    }
    public static Object getInstanceByName(String a) throws Exception{
        return getForce(a, new Exception());
    }
    public static Class getClassByConfig(String a) throws Exception{
        return getClassByName(getNameByConfig(a));
    }
    public static Class getClassByName(String a) throws Exception{
        //DebugPrint("Class Load: "+ a);
        return Class.forName(a);
    }
    public static String getNameByConfig(String a){
        String b=(String)config.get(a);
        if ( b == null )
            DebugPrint("getNameByConfig Fail: : " + a);
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
        if ( key.equals("KeyExchangeDHEC521") ) return (Object)(new KeyExchangeDHEC521());        
        if ( key.equals("KeyExchangeECDHN") ) return (Object)(new KeyExchangeECDHN());
        if ( key.equals("HMACSHA1") ) return (Object)(new HMACSHA1());
        if ( key.equals("HASHSHA512") ) return (Object)(new HASHSHA512());
        if ( key.equals("SignatureRSA") ) return (Object)(new SignatureRSA());
        if ( key.equals("Random") ) return (Object)(new Random());        
        if ( key.equals("CipherAES256CTR") ) return (Object)(new CipherAES256CTR());
        if ( key.equals("UserAuthNone") ) return (Object)(new UserAuthNone());
        if ( key.equals("UserAuthPassword") ) return (Object)(new UserAuthPassword());
      
        DebugPrint("FailLoadClass !! " + key);
        throw e;
    }
 
    static java.util.Hashtable config=new java.util.Hashtable();
    static{
        config.put("ecdh-sha2-nistp521","KeyExchangeDHEC521");        
        config.put("ecdh-sha2-nistp","KeyExchangeECDHN");        
        
        config.put("hmac-sha1","HMACSHA1");
        config.put("sha-512","HASHSHA512");
        config.put("signature.rsa","SignatureRSA");
        config.put("random","Random");
        config.put("aes256-ctr","CipherAES256CTR");
        config.put("userauth.none","UserAuthNone");
        config.put("userauth.password","UserAuthPassword");
        
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
