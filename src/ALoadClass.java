class ALoadClass {
    public static String getNameByConfig(String a){
        return (String)config.get(a);
    }    
    public static void DebugPrintException(String a) {
        System.out.println("       " + a);        
    }
 
    static java.util.Hashtable config=new java.util.Hashtable();
    static{
        config.put("cipher.s2c","aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-ctr,aes192-cbc,aes256-ctr,aes256-cbc");
        config.put("cipher.c2s","aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-ctr,aes192-cbc,aes256-ctr,aes256-cbc");
        config.put("CheckCiphers","aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-ctr,arcfour,arcfour128,arcfour256");
        config.put("kex","ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1");
        config.put("CheckKexes","diffie-hellman-group14-sha1,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521");
        config.put("server_host_key","ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");
        config.put("CheckSignatures","ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521");
        config.put("mac.c2s","hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96");
        config.put("mac.s2c","hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha1-96,hmac-md5-96");
        config.put("compression.c2s","none");
        config.put("compression.s2c","none");
        config.put("lang.c2s","");
        config.put("lang.s2c","");
        config.put("StrictHostKeyChecking","ask");
        config.put("HashKnownHosts","no");
        config.put("MaxAuthTries","6");
        config.put("PreferredAuthentications","gssapi-with-mic,publickey,keyboard-interactive,password");
    }    
}
