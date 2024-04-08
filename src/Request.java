abstract class Request{
  private Session session=null;
  private Channel channel=null;
  void request(Session session, Channel channel) throws Exception{
    this.session=session;
    this.channel=channel;
  }
}
