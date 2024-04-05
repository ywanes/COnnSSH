import java.math.BigInteger;

public class KeyPairRSA{
  public static final int ERROR=0;
  public static final int DSA=1;
  public static final int RSA=2;
  public static final int ECDSA=3;
  public static final int UNKNOWN=4;
  static final int VENDOR_OPENSSH=0;
  int vendor=VENDOR_OPENSSH;
  protected String publicKeyComment = "no comment";  
  protected boolean encrypted=false;
  protected byte[] data=null;
  private byte[] n_array;   
  private byte[] pub_array; 
  private byte[] prv_array; 
  private byte[] p_array;  
  private byte[] q_array;  
  private byte[] ep_array; 
  private byte[] eq_array; 
  private byte[] c_array;  
  private int key_size=1024;
  private static final byte[] sshrsa=str2byte("ssh-rsa");
  
  public static KeyPairRSA genKeyPair(int type) throws JSchException{
    return genKeyPair(type, 1024);
  }
  public static KeyPairRSA genKeyPair(int type, int key_size) throws JSchException{
    KeyPairRSA kpair=null;
    if(type==DSA){}
    else if(type==RSA){ kpair=new KeyPairRSA(); }
    if(kpair!=null){
      kpair.generate(key_size);
    }
    return kpair;
  }
  void generate(int key_size) throws JSchException{
    System.out.println("removido");
  }
  public String getPublicKeyComment(){
    return publicKeyComment;
  }
  public void setPublicKeyComment(String publicKeyComment){
    this.publicKeyComment = publicKeyComment;
  }
  private byte[] encrypt(byte[] plain, byte[][] _iv, byte[] passphrase){
      return null;
  }
  private byte[] decrypt(byte[] data, byte[] passphrase, byte[] iv){
    return null;
  }
  int writeSEQUENCE(byte[] buf, int index, int len){
    return 0;
  }
  int writeINTEGER(byte[] buf, int index, byte[] data){
    return 0;
  }
  int writeOCTETSTRING(byte[] buf, int index, byte[] data){
    return 0;
  }
  int writeDATA(byte[] buf, byte n, int index, byte[] data){
    return 0;
  }
  int countLength(int len){
    return 0;
  }
  int writeLength(byte[] data, int index, int len){
    return 0;
  }
  private Random genRandom(){
    return null;
  }
  synchronized byte[] genKey(byte[] passphrase, byte[] iv){
    return null;
  } 
  public boolean isEncrypted(){ 
    return encrypted; 
  }
  public boolean decrypt(String _passphrase){
    if(_passphrase==null || _passphrase.length()==0)
      return !encrypted;
    return decrypt(str2byte(_passphrase));
  }
  public boolean decrypt(byte[] _passphrase){
      return false;
  }
  public static KeyPairRSA load(JSch jsch, String prvkey) throws JSchException{
    return null;
  }
  public static KeyPairRSA load(JSch jsch, String prvfile, String pubfile) throws JSchException{
      return null;
  }
  public static KeyPairRSA load(JSch jsch, byte[] prvkey, byte[] pubkey) throws JSchException{
    return null;
  }
  static private byte a2b(byte c){
    return (byte)0;
  }
  static private byte b2a(byte c){
    return (byte)0;
  }
  static KeyPairRSA loadPPK(byte[] buf) throws JSchException {
    byte[] pubkey = null;
    byte[] prvkey = null;
    int lines = 0;
    Buffer buffer = new Buffer(buf);
    java.util.Hashtable v = new java.util.Hashtable();
    while(true){
      if(!parseHeader(buffer, v))
        break;
    } 
    String typ = (String)v.get("PuTTY-User-Key-File-2");
    if(typ == null)
      return null;
    lines = Integer.parseInt((String)v.get("Public-Lines"));
    pubkey = parseLines(buffer, lines); 
    while(parseHeader(buffer, v)){}
    lines = Integer.parseInt((String)v.get("Private-Lines"));
    prvkey = parseLines(buffer, lines); 
    while(parseHeader(buffer, v)){}
    return null;
  }
  private static byte[] parseLines(Buffer buffer, int lines){
    byte[] buf = buffer.buffer;
    int index = buffer.index;
    byte[] data = null;
    int i = index;
    while(lines-->0){
      while(buf.length > i){
        if(buf[i++] == 0x0d){
          if(data == null){
            data = new byte[i - index - 1];
            System.arraycopy(buf, index, data, 0, i - index - 1);
          }
          else {
            byte[] tmp = new byte[data.length + i - index - 1];
            System.arraycopy(data, 0, tmp, 0, data.length);
            System.arraycopy(buf, index, tmp, data.length, i - index -1);
            for(int j = 0; j < data.length; j++) data[j] = 0; // clear
            data = tmp;
          } 
          break;
        }
      }
      if(buf[i]==0x0a)
        i++;
      index=i;
    }

    if(data != null)
      buffer.index = index;

    return data;
  }
  private static boolean parseHeader(Buffer buffer, java.util.Hashtable v){
    byte[] buf = buffer.buffer;
    int index = buffer.index;
    String key = null;
    String value = null;
    for(int i = index; i < buf.length; i++){
      if(buf[i] == 0x0d){
        break;
      }
      if(buf[i] == ':'){
        key = new String(buf, index, i - index);
        i++;
        if(i < buf.length && buf[i] == ' '){
          i++;
        }
        index = i;
        break;
      }
    }
    if(key == null)
      return false;
    for(int i = index; i < buf.length; i++){
      if(buf[i] == 0x0d){
        value = new String(buf, index, i - index);
        i++;
        if(i < buf.length && buf[i] == 0x0a){
          i++;
        }
        index = i;
        break;
      }
    }
    if(value != null){
      v.put(key, value);
      buffer.index = index;
    }
    return (key != null && value != null);
  }
  class ASN1Exception extends Exception {
  }
  class ASN1{
    byte[] buf;
    int start;
    int length;
    ASN1(byte[] buf) throws ASN1Exception {
      this(buf, 0, buf.length);
    }
    ASN1(byte[] buf, int start, int length) throws ASN1Exception {
      this.buf = buf;
      this.start = start;
      this.length = length;
      if(start+length>buf.length)
        throw new ASN1Exception();
    }
    int getType() {
      return buf[start]&0xff;
    }
    boolean isSEQUENCE() {
      return getType()==(0x30&0xff);
    }
    boolean isINTEGER() {
      return getType()==(0x02&0xff);
    }
    boolean isOBJECT() {
      return getType()==(0x06&0xff);
    }
    boolean isOCTETSTRING() {
      return getType()==(0x04&0xff);
    }
    private int getLength(int[] indexp) {
      int index=indexp[0];
      int length=buf[index++]&0xff;
      if((length&0x80)!=0) {
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(buf[index++]&0xff); }
      }
      indexp[0]=index;
      return length;
    }
    byte[] getContent() {
      int[] indexp=new int[1];
      indexp[0]=start+1;
      int length = getLength(indexp);
      int index=indexp[0];
      byte[] tmp = new byte[length];
      System.arraycopy(buf, index, tmp, 0, tmp.length);
      return tmp;
    }
    ASN1[] getContents() throws ASN1Exception {
      return null;
    }
  }
  public KeyPairRSA(){
    this(null, null, null);
  }
  public KeyPairRSA(byte[] n_array,byte[] pub_array,byte[] prv_array){
    this.n_array = n_array;
    this.pub_array = pub_array;
    this.prv_array = prv_array;
    if(n_array!=null){
      key_size = (new java.math.BigInteger(n_array)).bitLength();
    }
  }
  byte[] getPrivateKey(){
    int content=
      1+countLength(1) + 1 +                           // INTEGER
      1+countLength(n_array.length) + n_array.length + // INTEGER  N
      1+countLength(pub_array.length) + pub_array.length + // INTEGER  pub
      1+countLength(prv_array.length) + prv_array.length+  // INTEGER  prv
      1+countLength(p_array.length) + p_array.length+      // INTEGER  p
      1+countLength(q_array.length) + q_array.length+      // INTEGER  q
      1+countLength(ep_array.length) + ep_array.length+    // INTEGER  ep
      1+countLength(eq_array.length) + eq_array.length+    // INTEGER  eq
      1+countLength(c_array.length) + c_array.length;      // INTEGER  c

    int total=
      1+countLength(content)+content;   // SEQUENCE

    byte[] plain=new byte[total];
    int index=0;
    index=writeSEQUENCE(plain, index, content);
    index=writeINTEGER(plain, index, new byte[1]);  // 0
    index=writeINTEGER(plain, index, n_array);
    index=writeINTEGER(plain, index, pub_array);
    index=writeINTEGER(plain, index, prv_array);
    index=writeINTEGER(plain, index, p_array);
    index=writeINTEGER(plain, index, q_array);
    index=writeINTEGER(plain, index, ep_array);
    index=writeINTEGER(plain, index, eq_array);
    index=writeINTEGER(plain, index, c_array);
    return plain;
  }
  boolean parse(byte [] plain){
      return false;
  }
  public byte[] getPublicKeyBlob(){
    byte[] foo=getPublicKeyBlob();
    if(foo!=null)
      return foo;
    if(pub_array==null) return null;
    byte[][] tmp = new byte[3][];
    tmp[0] = sshrsa;
    tmp[1] = pub_array;
    tmp[2] = n_array;
    return Buffer.fromBytes(tmp).buffer;
  }
  byte[] getKeyTypeName(){
    return sshrsa;
  }
  public int getKeyType(){
    return RSA;
  }
  public byte[] getSignature(byte[] data){
    try{      
      SignatureRSA rsa=(SignatureRSA)ALoadClass.getInstanceByConfig("signature.rsa");
      rsa.init();
      rsa.setPrvKey(prv_array, n_array);
      rsa.update(data);
      byte[] sig = rsa.sign();
      byte[][] tmp = new byte[2][];
      tmp[0] = sshrsa;
      tmp[1] = sig;
      return Buffer.fromBytes(tmp).buffer;
    }catch(Exception e){
        ALoadClass.DebugPrintException("ex_122");
    }
    return null;
  }
  public SignatureRSA getVerifier(){
    try{      
      SignatureRSA rsa=(SignatureRSA)ALoadClass.getInstanceByConfig("signature.rsa");
      rsa.init();
      if(pub_array == null && n_array == null && getPublicKeyBlob()!=null){
        Buffer buf = new Buffer(getPublicKeyBlob());
        buf.getString();
        pub_array = buf.getString();
        n_array = buf.getString();
      } 
      rsa.setPubKey(pub_array, n_array);
      return rsa;
    }catch(Exception e){
        ALoadClass.DebugPrintException("ex_123");
    }
    return null;
  }
  static KeyPairRSA fromSSHAgent(Buffer buf) throws JSchException {
    byte[][] tmp = buf.getBytes(8, "invalid key format");
    byte[] n_array = tmp[1];
    byte[] pub_array = tmp[2];
    byte[] prv_array = tmp[3];
    KeyPairRSA kpair = new KeyPairRSA(n_array, pub_array, prv_array);
    kpair.c_array = tmp[4];     // iqmp
    kpair.p_array = tmp[5];
    kpair.q_array = tmp[6];
    kpair.publicKeyComment = new String(tmp[7]);
    kpair.vendor=VENDOR_OPENSSH;
    return kpair;
  }

  public byte[] forSSHAgent() throws JSchException {
    if(isEncrypted())
      throw new JSchException("key is encrypted.");
    Buffer buf = new Buffer();
    buf.putString(sshrsa);
    buf.putString(n_array);
    buf.putString(pub_array);
    buf.putString(prv_array);
    buf.putString(getCArray());
    buf.putString(p_array);
    buf.putString(q_array);
    buf.putString(str2byte(publicKeyComment));
    byte[] result = new byte[buf.getLength()];
    buf.getByte(result, 0, result.length);
    return result;
  }
  private byte[] getEPArray(){
    if(ep_array==null)
      ep_array=(new BigInteger(prv_array)).mod(new BigInteger(p_array).subtract(BigInteger.ONE)).toByteArray();
    return ep_array;
  } 
  private byte[] getEQArray(){
    if(eq_array==null)
      eq_array=(new BigInteger(prv_array)).mod(new BigInteger(q_array).subtract(BigInteger.ONE)).toByteArray();
    return eq_array;
  } 
  private byte[] getCArray(){
    if(c_array==null)
      c_array=(new BigInteger(q_array)).modInverse(new BigInteger(p_array)).toByteArray();
    return c_array;
  } 

  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
