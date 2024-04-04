import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;

public class PBKDF{
  public byte[] getKey(byte[] _pass, byte[] salt, int iterations, int size){
    char[] pass=new char[_pass.length];
    for(int i = 0; i < _pass.length; i++){
      pass[i]=(char)(_pass[i]&0xff);
    }
    try {
      PBEKeySpec spec =
        new PBEKeySpec(pass, salt, iterations, size*8);
      SecretKeyFactory skf =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      byte[] key = skf.generateSecret(spec).getEncoded();
      return key;
    }
    catch(InvalidKeySpecException e){
    }
    catch(NoSuchAlgorithmException e){
    }
    return null;
  }
}
