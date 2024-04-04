class RequestShell extends Request{
  public void request(Session session, Channel channel) throws Exception{
    super.request(session, channel);
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(channel.getRecipient());
    buf.putString(Util.str2byte("shell"));
    buf.putByte((byte)(waitForReply() ? 1 : 0));
    write(packet);
  }
}
