// KeyExchangeDHEC521
public class KeyExchangeECDH521 {

  static final int PROPOSAL_KEX_ALGS=0;
  static final int PROPOSAL_SERVER_HOST_KEY_ALGS=1;
  static final int PROPOSAL_ENC_ALGS_CTOS=2;
  static final int PROPOSAL_ENC_ALGS_STOC=3;
  static final int PROPOSAL_MAC_ALGS_CTOS=4;
  static final int PROPOSAL_MAC_ALGS_STOC=5;
  static final int PROPOSAL_COMP_ALGS_CTOS=6;
  static final int PROPOSAL_COMP_ALGS_STOC=7;
  static final int PROPOSAL_LANG_CTOS=8;
  static final int PROPOSAL_LANG_STOC=9;
  static final int PROPOSAL_MAX=10;
  static String kex="diffie-hellman-group1-sha1";
  static String server_host_key="ssh-rsa,ssh-dss";
  static String enc_c2s="blowfish-cbc";
  static String enc_s2c="blowfish-cbc";
  static String mac_c2s="hmac-md5";
  static String mac_s2c="hmac-md5";
  static String lang_c2s="";
  static String lang_s2c="";
  public static final int STATE_END=0;
  protected Session session=null;
  protected HASHSHA512 sha=null;
  protected byte[] K=null;
  protected byte[] H=null;
  protected byte[] K_S=null;
  protected final int RSA=0;
  protected final int DSS=1;
  protected final int ECDSA=2;
  private int type=0;
  private String key_alg_name = "";


  private static final int SSH_MSG_KEX_ECDH_INIT = 30;
  private static final int SSH_MSG_KEX_ECDH_REPLY = 31;
  private int state;
  byte[] Q_C;
  byte[] V_S;
  byte[] V_C;
  byte[] I_S;
  byte[] I_C;
  byte[] e;
  private Buffer buf;
  private Packet packet;
  private KeyExchangeECDH ecdh;
  protected String sha_name="sha-512";
  protected int key_size=521;
  public void init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
    this.session=session;
    this.V_S=V_S;      
    this.V_C=V_C;      
    this.I_S=I_S;      
    this.I_C=I_C;      

    try{
      sha=new HASHSHA512();
      sha.init();
    }
    catch(Exception e){
      ALoadClass.DebugPrintException("ex_89");  
      System.err.println(e);
    }

    buf=new Buffer();
    packet=new Packet(buf);

    packet.reset();
    buf.putByte((byte)SSH_MSG_KEX_ECDH_INIT);

    try{
      ecdh=(KeyExchangeECDH)ALoadClass.getInstanceByConfig("ecdh-sha2-nistp");      
      ecdh.init(key_size);

      Q_C = ecdh.getQ();
      buf.putString(Q_C);
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_90");
      if(e instanceof Throwable)
        throw new JSchException(e.toString(), (Throwable)e);
      throw new JSchException(e.toString());
    }

    if(V_S==null){  // This is a really ugly hack for Session.checkKexes ;-(
      return;
    }

    session.write(packet);

    if(JSch.getLogger().isEnabled(Logger.INFO)){
      JSch.getLogger().log(Logger.INFO, 
                           "SSH_MSG_KEX_ECDH_INIT sent");
      JSch.getLogger().log(Logger.INFO, 
                           "expecting SSH_MSG_KEX_ECDH_REPLY");
    }

    state=SSH_MSG_KEX_ECDH_REPLY;
  }
  
  public String getKeyType() {
    if(type==DSS) return "DSA";
    if(type==RSA) return "RSA";
    return "ECDSA";
  }

  public String getKeyAlgorithName() {
    return key_alg_name;
  }

  protected static String[] guess(byte[]I_S, byte[]I_C){
    String[] guess=new String[PROPOSAL_MAX];
    Buffer sb=new Buffer(I_S); sb.setOffSet(17);
    Buffer cb=new Buffer(I_C); cb.setOffSet(17);

    if(JSch.getLogger().isEnabled(Logger.INFO)){
      for(int i=0; i<PROPOSAL_MAX; i++){
        JSch.getLogger().log(Logger.INFO,
                             "kex: server: "+Util.byte2str(sb.getString()));
      }
      for(int i=0; i<PROPOSAL_MAX; i++){
        JSch.getLogger().log(Logger.INFO,
                             "kex: client: "+Util.byte2str(cb.getString()));
      }
      sb.setOffSet(17);
      cb.setOffSet(17);
    }

    for(int i=0; i<PROPOSAL_MAX; i++){
      byte[] sp=sb.getString();  // server proposal
      byte[] cp=cb.getString();  // client proposal
      int j=0;
      int k=0;

      loop:
      while(j<cp.length){
	while(j<cp.length && cp[j]!=',')j++; 
	if(k==j) return null;
	String algorithm=Util.byte2str(cp, k, j-k);
	int l=0;
	int m=0;
	while(l<sp.length){
	  while(l<sp.length && sp[l]!=',')l++; 
	  if(m==l) return null;
	  if(algorithm.equals(Util.byte2str(sp, m, l-m))){
	    guess[i]=algorithm;
	    break loop;
	  }
	  l++;
	  m=l;
	}	
	j++;
	k=j;
      }
      if(j==0){
	guess[i]="";
      }
      else if(guess[i]==null){
	return null;
      }
    }

    if(JSch.getLogger().isEnabled(Logger.INFO)){
      JSch.getLogger().log(Logger.INFO, 
                           "kex: server->client"+
                           " "+guess[PROPOSAL_ENC_ALGS_STOC]+
                           " "+guess[PROPOSAL_MAC_ALGS_STOC]+
                           " "+guess[PROPOSAL_COMP_ALGS_STOC]);
      JSch.getLogger().log(Logger.INFO, 
                           "kex: client->server"+
                           " "+guess[PROPOSAL_ENC_ALGS_CTOS]+
                           " "+guess[PROPOSAL_MAC_ALGS_CTOS]+
                           " "+guess[PROPOSAL_COMP_ALGS_CTOS]);
    }

    return guess;
  }
  
  byte[] getK(){ return K; }
  byte[] getH(){ return H; }
  HASHSHA512 getHash(){ return sha; }
  byte[] getHostKey(){ return K_S; }

  /*
   * It seems JCE included in Oracle's Java7u6(and later) has suddenly changed
   * its behavior.  The secrete generated by KeyAgreement#generateSecret()
   * may start with 0, even if it is a positive value.
   */
  protected byte[] normalize(byte[] secret) {
    if(secret.length > 1 &&
       secret[0] == 0 && (secret[1]&0x80) == 0) {
      byte[] tmp=new byte[secret.length-1];
      System.arraycopy(secret, 1, tmp, 0, tmp.length);
      return normalize(tmp);
    }
    else {
      return secret;
    }
  }

  protected boolean verify(String alg, byte[] K_S, int index,
                           byte[] sig_of_H) throws Exception {
    int i,j;

    i=index;
    boolean result=false;

    if(alg.equals("ssh-rsa")){
      byte[] tmp;
      byte[] ee;
      byte[] n;

      type=RSA;
      key_alg_name=alg;
      
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|
        ((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      tmp=new byte[j]; System.arraycopy(K_S, i, tmp, 0, j); i+=j;
      ee=tmp;
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|
        ((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      tmp=new byte[j]; System.arraycopy(K_S, i, tmp, 0, j); i+=j;
      n=tmp;
	
      SignatureRSA sig=null;
      try{
        sig=(SignatureRSA)ALoadClass.getInstanceByConfig("signature.rsa");
        sig.init();
      }
      catch(Exception e){
          ALoadClass.DebugPrintException("ex_86");
        System.err.println(e);
      }
      sig.setPubKey(ee, n);   
      sig.update(H);
      result=sig.verify(sig_of_H);

      if(JSch.getLogger().isEnabled(Logger.INFO)){
        JSch.getLogger().log(Logger.INFO, 
                             "ssh_rsa_verify: signature "+result);
      }
    }else{
      System.err.println("unknown alg");
    }	    

    return result;
  }

  public boolean next(Buffer _buf) throws Exception{
    int i,j;
    switch(state){
    case SSH_MSG_KEX_ECDH_REPLY:
      // The server responds with:
      // byte     SSH_MSG_KEX_ECDH_REPLY
      // string   K_S, server's public host key
      // string   Q_S, server's ephemeral public key octet string
      // string   the signature on the exchange hash
      j=_buf.getInt();
      j=_buf.getByte();
      j=_buf.getByte();
      if(j!=31){
	System.err.println("type: must be 31 "+j);
	return false;
      }

      K_S=_buf.getString();

      byte[] Q_S=_buf.getString();

      //byte[][] r_s = KeyPairECDSA.fromPoint(Q_S);
      byte[][] r_s = fromPoint(Q_S);

      // RFC 5656,
      // 4. ECDH Key Exchange
      //   All elliptic curve public keys MUST be validated after they are
      //   received.  An example of a validation algorithm can be found in
      //   Section 3.2.2 of [SEC1].  If a key fails validation,
      //   the key exchange MUST fail.
      if(!ecdh.validate(r_s[0], r_s[1])){
	return false;
      }

      K = ecdh.getSecret(r_s[0], r_s[1]);
      K=normalize(K);

      byte[] sig_of_H=_buf.getString();
      buf.reset();
      buf.putString(V_C); buf.putString(V_S);
      buf.putString(I_C); buf.putString(I_S);
      buf.putString(K_S);
      buf.putString(Q_C); buf.putString(Q_S);
      buf.putMPInt(K);
      byte[] foo=new byte[buf.getLength()];
      buf.getByte(foo);

      sha.update(foo, 0, foo.length);
      H=sha.digest();

      i=0;
      j=0;
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|
	((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      String alg=Util.byte2str(K_S, i, j);
      i+=j;

      boolean result = verify(alg, K_S, i, sig_of_H);

      state=STATE_END;
      return result;
    }
    return false;
  }

  static byte[][] fromPoint(byte[] point) {
    int i = 0;
    while(point[i]!=4) i++;
    i++;
    byte[][] tmp = new byte[2][];
    byte[] r_array = new byte[(point.length-i)/2];
    byte[] s_array = new byte[(point.length-i)/2];
    System.arraycopy(point, i, r_array, 0, r_array.length);
    System.arraycopy(point, i+r_array.length, s_array, 0, s_array.length);
    tmp[0] = r_array;
    tmp[1] = s_array;
    return tmp;
  }
  
  public int getState(){return state; }
}
