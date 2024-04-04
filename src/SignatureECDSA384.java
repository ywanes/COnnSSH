import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class SignatureECDSA384 extends SignatureECDSAN {
  String getName() {
    return "ecdsa-sha2-nistp384";
  }
}
