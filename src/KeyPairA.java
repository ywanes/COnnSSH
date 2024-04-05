import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;

public abstract class KeyPairA{
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

  public static KeyPairA genKeyPair(JSch jsch, int type) throws JSchException{
    return genKeyPair(jsch, type, 1024);
  }
  public static KeyPairA genKeyPair(JSch jsch, int type, int key_size) throws JSchException{
    KeyPairA kpair=null;
    if(type==DSA){ kpair=new KeyPairDSA(jsch); }
    else if(type==RSA){ kpair=new KeyPairRSA(jsch); }
    else if(type==ECDSA){ kpair=new KeyPairECDSA(jsch); }
    if(kpair!=null){
      kpair.generate(key_size);
    }
    return kpair;
  }

  abstract void generate(int key_size) throws JSchException;

  abstract byte[] getBegin();
  abstract byte[] getEnd();
  abstract int getKeySize();

  public abstract byte[] getSignature(byte[] data);
  public abstract Signature getVerifier();

  public abstract byte[] forSSHAgent() throws JSchException;

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

  public KeyPairA(JSch jsch){
    this.jsch=jsch;
  }

  static byte[][] header={Util.str2byte("Proc-Type: 4,ENCRYPTED"),
                          Util.str2byte("DEK-Info: DES-EDE3-CBC,")};

  abstract byte[] getPrivateKey();

  public void writePrivateKey(java.io.OutputStream out){
    this.writePrivateKey(out, null);
  }

  public void writePrivateKey(java.io.OutputStream out, byte[] passphrase){}

  private static byte[] space=Util.str2byte(" ");

  abstract byte[] getKeyTypeName();
  public abstract int getKeyType();

  public byte[] getPublicKeyBlob() {
    return publickeyblob;
  }

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

  abstract boolean parse(byte[] data);

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

  public static KeyPairA load(JSch jsch, String prvkey) throws JSchException{
    return null;
  }
  public static KeyPairA load(JSch jsch, String prvfile, String pubfile) throws JSchException{
      return null;
  }

  public static KeyPairA load(JSch jsch, byte[] prvkey, byte[] pubkey) throws JSchException{
    return null;
  }

  static private byte a2b(byte c){
    return (byte)0;
  }
  static private byte b2a(byte c){
    return (byte)0;
  }

  public void dispose(){
    Util.bzero(passphrase);
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

  static KeyPairA loadPPK(JSch jsch, byte[] buf) throws JSchException {
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

    KeyPairA kpair = null;

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
    else if(typ.equals("ssh-dss")){
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
    }
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
}
