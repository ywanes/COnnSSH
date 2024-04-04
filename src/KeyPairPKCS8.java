import java.util.Vector;
import java.math.BigInteger;

public class KeyPairPKCS8 extends KeyPairA {
  private static final byte[] rsaEncryption = {
    (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86,
    (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01
  };

  private static final byte[] dsaEncryption = {
    (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce,
    (byte)0x38, (byte)0x04, (byte)0x1
  };

  private static final byte[] pbes2 = {
    (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
    (byte)0x0d, (byte)0x01, (byte)0x05, (byte)0x0d 
  };

  private static final byte[] pbkdf2 = {
    (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
    (byte)0x0d, (byte)0x01, (byte)0x05, (byte)0x0c 
  };

  private static final byte[] aes128cbc = {
    (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
    (byte)0x03, (byte)0x04, (byte)0x01, (byte)0x02 
  };

  private static final byte[] aes192cbc = {
    (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
    (byte)0x03, (byte)0x04, (byte)0x01, (byte)0x16 
  };

  private static final byte[] aes256cbc = {
    (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
    (byte)0x03, (byte)0x04, (byte)0x01, (byte)0x2a 
  };

  private static final byte[] pbeWithMD5AndDESCBC = {
    (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7,
    (byte)0x0d, (byte)0x01, (byte)0x05, (byte)0x03
  };

  private KeyPairA kpair = null;

  public KeyPairPKCS8(JSch jsch){
    super(jsch);
  }

  void generate(int key_size) throws JSchException{
  }

  private static final byte[] begin=Util.str2byte("-----BEGIN DSA PRIVATE KEY-----");
  private static final byte[] end=Util.str2byte("-----END DSA PRIVATE KEY-----");

  byte[] getBegin(){ return begin; }
  byte[] getEnd(){ return end; }

  byte[] getPrivateKey(){
    return null;
  }

  boolean parse(byte[] plain){

    /* from RFC5208
      PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL 
      }
      Version ::= INTEGER
      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
      PrivateKey ::= OCTET STRING
      Attributes ::= SET OF Attribute
    }
    */

    try{
      Vector values = new Vector();

      ASN1[] contents = null;
      ASN1 asn1 = new ASN1(plain);
      contents = asn1.getContents();

      ASN1 privateKeyAlgorithm = contents[1];
      ASN1 privateKey = contents[2];

      contents = privateKeyAlgorithm.getContents();
      byte[] privateKeyAlgorithmID = contents[0].getContent();
      contents = contents[1].getContents();
      if(contents.length>0){
        for(int i = 0; i < contents.length; i++){
          values.addElement(contents[i].getContent());
        }
      }

      byte[] _data = privateKey.getContent();

      KeyPairA _kpair = null;
      if(Util.array_equals(privateKeyAlgorithmID, rsaEncryption)){
        _kpair = new KeyPairRSA(jsch);
        _kpair.copy(this);
        if(_kpair.parse(_data)){
          kpair = _kpair;
        } 
      }
      else if(Util.array_equals(privateKeyAlgorithmID, dsaEncryption)){
        asn1 = new ASN1(_data);
        if(values.size() == 0) {  // embedded DSA parameters format
          /*
             SEQUENCE
               SEQUENCE
                 INTEGER    // P_array
                 INTEGER    // Q_array
                 INTEGER    // G_array
               INTEGER      // prv_array
          */
          contents = asn1.getContents();
          byte[] bar = contents[1].getContent();
          contents = contents[0].getContents();
          for(int i = 0; i < contents.length; i++){
            values.addElement(contents[i].getContent());
          }
          values.addElement(bar);
        }
        else {
          /*
             INTEGER      // prv_array
          */
          values.addElement(asn1.getContent());
        }

        byte[] P_array = (byte[])values.elementAt(0);
        byte[] Q_array = (byte[])values.elementAt(1);
        byte[] G_array = (byte[])values.elementAt(2);
        byte[] prv_array = (byte[])values.elementAt(3);
        // Y = g^X mode p
        byte[] pub_array =
          (new BigInteger(G_array)).
            modPow(new BigInteger(prv_array), new BigInteger(P_array)).
            toByteArray();

        KeyPairDSA _key = new KeyPairDSA(jsch,
                                         P_array, Q_array, G_array,
                                         pub_array, prv_array);
        plain = _key.getPrivateKey();

        _kpair = new KeyPairDSA(jsch);
        _kpair.copy(this);
        if(_kpair.parse(plain)){
          kpair = _kpair;
        }
      }
    }
    catch(ASN1Exception e){
      return false;
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_117");
      return false;
    }
    return kpair != null;
  }

  public byte[] getPublicKeyBlob(){
    return kpair.getPublicKeyBlob();
  }

  byte[] getKeyTypeName(){ return kpair.getKeyTypeName();}
  public int getKeyType(){return kpair.getKeyType();}

  public int getKeySize(){
    return kpair.getKeySize();
  }

  public byte[] getSignature(byte[] data){
    return kpair.getSignature(data);
  }

  public Signature getVerifier(){
    return kpair.getVerifier();
  }

  public byte[] forSSHAgent() throws JSchException {
    return kpair.forSSHAgent();
  }

  public boolean decrypt(byte[] _passphrase){
    System.out.println("removido");
    return false;
  }

  Cipher getCipher(byte[] id){
    Cipher cipher=null;
    String name = null;
    try{
      if(Util.array_equals(id, aes128cbc)){
        name="aes128-cbc";
      }
      else if(Util.array_equals(id, aes192cbc)){
        name="aes192-cbc";
      }
      else if(Util.array_equals(id, aes256cbc)){
        name="aes256-cbc";
      }
      cipher=(Cipher)ALoadClass.getInstanceByConfig(name);
    }
    catch(Exception e){
        ALoadClass.DebugPrintException("ex_119");
      if(JSch.getLogger().isEnabled(Logger.FATAL)){
        String message="";
        if(name==null){
          message="unknown oid: "+Util.toHex(id);
        }
        else {
          message="function "+name+" is not supported";
        }
        JSch.getLogger().log(Logger.FATAL, "PKCS8: "+message);
      }
    }
    return cipher;
  }
}
