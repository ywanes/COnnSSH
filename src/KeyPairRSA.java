import java.math.BigInteger;

public class KeyPairRSA{// extends KeyPairA{
    
  public static final int ERROR=0;
  public static final int DSA=1;
  public static final int RSA=2;
  public static final int ECDSA=3;
  public static final int UNKNOWN=4;

  static final int VENDOR_OPENSSH=0;
  static final int VENDOR_FSECURE=1;
  static final int VENDOR_PUTTY=2;
  static final int VENDOR_PKCS8=3;

  int vendor=VENDOR_OPENSSH;

  private static final byte[] cr=Util.str2byte("\n");

  public static KeyPairRSA genKeyPair(JSch jsch, int type) throws JSchException{
    return genKeyPair(jsch, type, 1024);
  }
  public static KeyPairRSA genKeyPair(JSch jsch, int type, int key_size) throws JSchException{
    KeyPairRSA kpair=null;
    if(type==DSA){}
    else if(type==RSA){ kpair=new KeyPairRSA(jsch); }
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

  protected String publicKeyComment = "no comment";

  JSch jsch=null;
  private HASHSHA512 hash;
  private Random random;

  private byte[] passphrase;

  static byte[][] header={Util.str2byte("Proc-Type: 4,ENCRYPTED"),
                          Util.str2byte("DEK-Info: DES-EDE3-CBC,")};

  public void writePrivateKey(java.io.OutputStream out){
    this.writePrivateKey(out, null);
  }

  public void writePrivateKey(java.io.OutputStream out, byte[] passphrase){}
  private static byte[] space=Util.str2byte(" ");
  
  public void writePublicKey(java.io.OutputStream out, String comment){
    byte[] pubblob=getPublicKeyBlob();
    byte[] pub=Util.toBase64(pubblob, 0, pubblob.length);
    try{
      out.write(getKeyTypeName()); out.write(space);
      out.write(pub, 0, pub.length); out.write(space);
      out.write(Util.str2byte(comment));
      out.write(cr);
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_99");
    }
  }

  public void writePublicKey(String name, String comment) throws java.io.FileNotFoundException, java.io.IOException{
  }

  public void writeSECSHPublicKey(java.io.OutputStream out, String comment){
  }

  /**
   * Writes the public key with the specified comment to the output stream in
   * the format defined in http://www.ietf.org/rfc/rfc4716.txt
   * @param name file name
   * @param comment comment
   * @see #writeSECSHPublicKey(java.io.OutputStream out, String comment)
   */
  public void writeSECSHPublicKey(String name, String comment) throws java.io.FileNotFoundException, java.io.IOException{
  }

  /**
   * Writes the plain private key to the file.
   * @param name file name
   * @see #writePrivateKey(String name,  byte[] passphrase)
   */
  public void writePrivateKey(String name) throws java.io.FileNotFoundException, java.io.IOException{
  }

  /**
   * Writes the cyphered private key to the file.
   * @param name file name
   * @param passphrase a passphrase to encrypt the private key
   * @see #writePrivateKey(java.io.OutputStream out,  byte[] passphrase)
   */
  public void writePrivateKey(String name, byte[] passphrase) throws java.io.FileNotFoundException, java.io.IOException{
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

  protected boolean encrypted=false;
  protected byte[] data=null;
  private byte[] iv=null;
  private byte[] publickeyblob=null;

  public boolean isEncrypted(){ return encrypted; }
  public boolean decrypt(String _passphrase){
    if(_passphrase==null || _passphrase.length()==0){
      return !encrypted;
    }
    return decrypt(Util.str2byte(_passphrase));
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

  public void finalize (){
    dispose();
  }

  private static final String[] header1 = {
    "PuTTY-User-Key-File-2: ",
    "Encryption: ",
    "Comment: ",
    "Public-Lines: "
  };

  private static final String[] header2 = {
    "Private-Lines: "
  };

  private static final String[] header3 = {
    "Private-MAC: "
  };

  static KeyPairRSA loadPPK(JSch jsch, byte[] buf) throws JSchException {
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
    if(typ == null){
      return null;
    }

    lines = Integer.parseInt((String)v.get("Public-Lines"));
    pubkey = parseLines(buffer, lines); 

    while(true){
      if(!parseHeader(buffer, v))
        break;
    } 
    
    lines = Integer.parseInt((String)v.get("Private-Lines"));
    prvkey = parseLines(buffer, lines); 

    while(true){
      if(!parseHeader(buffer, v))
        break;
    } 

    prvkey = Util.fromBase64(prvkey, 0, prvkey.length);
    pubkey = Util.fromBase64(pubkey, 0, pubkey.length);

    KeyPairRSA kpair = null;

    if(typ.equals("ssh-rsa")) {

      Buffer _buf = new Buffer(pubkey);
      _buf.skip(pubkey.length);

      int len = _buf.getInt();
      _buf.getByte(new byte[len]);             // ssh-rsa
      byte[] pub_array = new byte[_buf.getInt()];
      _buf.getByte(pub_array);
      byte[] n_array = new byte[_buf.getInt()];
      _buf.getByte(n_array);

      kpair = new KeyPairRSA(jsch, n_array, pub_array, null);
    }
    /*else if(typ.equals("ssh-dss")){
      Buffer _buf = new Buffer(pubkey);
      _buf.skip(pubkey.length);

      int len = _buf.getInt();
      _buf.getByte(new byte[len]);              // ssh-dss

      byte[] p_array = new byte[_buf.getInt()];
      _buf.getByte(p_array);
      byte[] q_array = new byte[_buf.getInt()];
      _buf.getByte(q_array);
      byte[] g_array = new byte[_buf.getInt()];
      _buf.getByte(g_array);
      byte[] y_array = new byte[_buf.getInt()];
      _buf.getByte(y_array);

      kpair = new KeyPairDSA(jsch, p_array, q_array, g_array, y_array, null);
    }*/
    else {
      return null;
    }

    if(kpair == null)
      return null;

    kpair.encrypted = !v.get("Encryption").equals("none");
    kpair.vendor = VENDOR_PUTTY;
    kpair.publicKeyComment = (String)v.get("Comment");
    kpair.data = prvkey;
    kpair.parse(prvkey);
    return kpair;
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

/*  
  void copy(KeyPairA kpair){
    this.publickeyblob=kpair.publickeyblob;
    this.vendor=kpair.vendor;
    this.publicKeyComment=kpair.publicKeyComment;
    this.cipher=kpair.cipher;
  }
*/
  
  class ASN1Exception extends Exception {
  }

  class ASN1 {
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
    
  private byte[] n_array;   // modulus   p multiply q
  private byte[] pub_array; // e         
  private byte[] prv_array; // d         e^-1 mod (p-1)(q-1)

  private byte[] p_array;  // prime p
  private byte[] q_array;  // prime q
  private byte[] ep_array; // prime exponent p  dmp1 == prv mod (p-1)
  private byte[] eq_array; // prime exponent q  dmq1 == prv mod (q-1)
  private byte[] c_array;  // coefficient  iqmp == modinv(q, p) == q^-1 mod p

  private int key_size=1024;

  public KeyPairRSA(JSch jsch){
    this(jsch, null, null, null);
  }

  public KeyPairRSA(JSch jsch,
                    byte[] n_array,
                    byte[] pub_array,
                    byte[] prv_array){
    this.jsch=jsch;
    this.n_array = n_array;
    this.pub_array = pub_array;
    this.prv_array = prv_array;
    if(n_array!=null){
      key_size = (new java.math.BigInteger(n_array)).bitLength();
    }
  }

  private static final byte[] begin=Util.str2byte("-----BEGIN RSA PRIVATE KEY-----");
  private static final byte[] end=Util.str2byte("-----END RSA PRIVATE KEY-----");

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
  
  /*
  boolean parse(byte [] plain){

    try{
      int index=0;
      int length=0;

      if(vendor==VENDOR_PUTTY){
        Buffer buf = new Buffer(plain);
        buf.skip(plain.length);

        try {
          byte[][] tmp = buf.getBytes(4, "");
          prv_array = tmp[0];
          p_array = tmp[1];
          q_array = tmp[2];
          c_array = tmp[3];
        }
        catch(JSchException e){
          return false;
        }

        getEPArray();
        getEQArray();

        return true;
      }

      if(vendor==VENDOR_FSECURE){
	if(plain[index]!=0x30){                  // FSecure
	  Buffer buf=new Buffer(plain);
	  pub_array=buf.getMPIntBits();
	  prv_array=buf.getMPIntBits();
	  n_array=buf.getMPIntBits();
	  byte[] u_array=buf.getMPIntBits();
	  p_array=buf.getMPIntBits();
	  q_array=buf.getMPIntBits();
          if(n_array!=null){
            key_size = (new java.math.BigInteger(n_array)).bitLength();
          }

          getEPArray();
          getEQArray();
          getCArray();

	  return true;
	}
	return false;
      }

      index++; // SEQUENCE
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }

      if(plain[index]!=0x02)return false;
      index++; // INTEGER
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      n_array=new byte[length];
      System.arraycopy(plain, index, n_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      pub_array=new byte[length];
      System.arraycopy(plain, index, pub_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      prv_array=new byte[length];
      System.arraycopy(plain, index, prv_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      p_array=new byte[length];
      System.arraycopy(plain, index, p_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      q_array=new byte[length];
      System.arraycopy(plain, index, q_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      ep_array=new byte[length];
      System.arraycopy(plain, index, ep_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      eq_array=new byte[length];
      System.arraycopy(plain, index, eq_array, 0, length);
      index+=length;

      index++;
      length=plain[index++]&0xff;
      if((length&0x80)!=0){
        int foo=length&0x7f; length=0;
        while(foo-->0){ length=(length<<8)+(plain[index++]&0xff); }
      }
      c_array=new byte[length];
      System.arraycopy(plain, index, c_array, 0, length);
      index+=length;

      if(n_array!=null){
        key_size = (new java.math.BigInteger(n_array)).bitLength();
      }

    }
    catch(Exception e){
      ALoadClass.DebugPrintException("ex_121");
      return false;
    }
    return true;
  }
  */

  public byte[] getPublicKeyBlob(){
    byte[] foo=getPublicKeyBlob();
    if(foo!=null) return foo;

    if(pub_array==null) return null;
    byte[][] tmp = new byte[3][];
    tmp[0] = sshrsa;
    tmp[1] = pub_array;
    tmp[2] = n_array;
    return Buffer.fromBytes(tmp).buffer;
  }

  private static final byte[] sshrsa=Util.str2byte("ssh-rsa");
  byte[] getKeyTypeName(){return sshrsa;}
  public int getKeyType(){return RSA;}

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
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_122");
    }
    return null;
  }

  public Signature getVerifier(){
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
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_123");
    }
    return null;
  }

  static KeyPairRSA fromSSHAgent(JSch jsch, Buffer buf) throws JSchException {

    byte[][] tmp = buf.getBytes(8, "invalid key format");

    byte[] n_array = tmp[1];
    byte[] pub_array = tmp[2];
    byte[] prv_array = tmp[3];
    KeyPairRSA kpair = new KeyPairRSA(jsch, n_array, pub_array, prv_array);
    kpair.c_array = tmp[4];     // iqmp
    kpair.p_array = tmp[5];
    kpair.q_array = tmp[6];
    kpair.publicKeyComment = new String(tmp[7]);
    kpair.vendor=VENDOR_OPENSSH;
    return kpair;
  }

  public byte[] forSSHAgent() throws JSchException {
    if(isEncrypted()){
      throw new JSchException("key is encrypted.");
    }
    Buffer buf = new Buffer();
    buf.putString(sshrsa);
    buf.putString(n_array);
    buf.putString(pub_array);
    buf.putString(prv_array);
    buf.putString(getCArray());
    buf.putString(p_array);
    buf.putString(q_array);
    buf.putString(Util.str2byte(publicKeyComment));
    byte[] result = new byte[buf.getLength()];
    buf.getByte(result, 0, result.length);
    return result;
  }

  private byte[] getEPArray(){
    if(ep_array==null){
      ep_array=(new BigInteger(prv_array)).mod(new BigInteger(p_array).subtract(BigInteger.ONE)).toByteArray();
    }
    return ep_array;
  } 

  private byte[] getEQArray(){
    if(eq_array==null){
      eq_array=(new BigInteger(prv_array)).mod(new BigInteger(q_array).subtract(BigInteger.ONE)).toByteArray();
    }
    return eq_array;
  } 

  private byte[] getCArray(){
    if(c_array==null){
      c_array=(new BigInteger(q_array)).modInverse(new BigInteger(p_array)).toByteArray();
    }
    return c_array;
  } 

  public void dispose(){    
    Util.bzero(passphrase);
    Util.bzero(prv_array);
  }
}
