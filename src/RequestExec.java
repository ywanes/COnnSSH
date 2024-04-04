class RequestExec extends Request{
  private byte[] command=new byte[0];
  RequestExec(byte[] command){
    this.command=command;
  }
  public void request(Session session, Channel channel) throws Exception{
    super.request(session, channel);
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(channel.getRecipient());
    buf.putString(Util.str2byte("exec"));
    buf.putByte((byte)(waitForReply() ? 1 : 0));
    buf.checkFreeSize(4+command.length);
    buf.putString(command);
    write(packet);
  }
}
