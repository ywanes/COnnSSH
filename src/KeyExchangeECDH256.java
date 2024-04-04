public class KeyExchangeECDH256 extends KeyExchangeECDHN implements KeyExchangeECDH {
  public void init() throws Exception {
    super.init(256);
  }
}
