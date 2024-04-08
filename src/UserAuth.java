public abstract class UserAuth{
  static final int SSH_MSG_USERAUTH_REQUEST=               50;
  static final int SSH_MSG_USERAUTH_FAILURE=               51;
  static final int SSH_MSG_USERAUTH_SUCCESS=               52;
  static final int SSH_MSG_USERAUTH_BANNER=                53;

  Packet packet;
  Buffer buf;
  String username;

  public void start(Session session) throws Exception{
    this.packet=session.packet;
    this.buf=packet.getBuffer();
    this.username=session.getUserName();
  }
}
