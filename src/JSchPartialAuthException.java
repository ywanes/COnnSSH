class JSchPartialAuthException extends JSchException{
  String methods;
  public JSchPartialAuthException () {
    super();
  }
  public JSchPartialAuthException (String s) {
    super(s);
    this.methods=s;
  }
  public String getMethods(){
    return methods;
  }
}
