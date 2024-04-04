import javax.crypto.*;
import javax.crypto.spec.*;

public class CipherARCFOUR implements Cipher{
  private static final int ivsize=8;
  private static final int bsize=16;
  private javax.crypto.Cipher cipher;    
  public int getIVSize(){return ivsize;} 
  public int getBlockSize(){return bsize;}
  public void init(int mode, byte[] key, byte[] iv) throws Exception{
    String pad="NoPadding";      
    byte[] tmp;
    if(key.length>bsize){
      tmp=new byte[bsize];
      System.arraycopy(key, 0, tmp, 0, tmp.length);
      key=tmp;
    }

    try{
      cipher=javax.crypto.Cipher.getInstance("RC4");
      SecretKeySpec _key = new SecretKeySpec(key, "RC4");
      synchronized(javax.crypto.Cipher.class){
        cipher.init((mode==ENCRYPT_MODE?
                     javax.crypto.Cipher.ENCRYPT_MODE:
                     javax.crypto.Cipher.DECRYPT_MODE),
		    _key);
      }
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_71");
      cipher=null;
      throw e;
    }
  }
  public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception{
    cipher.update(foo, s1, len, bar, s2);
  }
  public boolean isCBC(){return false; }
}
