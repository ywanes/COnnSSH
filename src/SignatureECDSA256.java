import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class SignatureECDSA256 extends SignatureECDSAN {
  String getName() {
    return "ecdsa-sha2-nistp256";
  }
}
