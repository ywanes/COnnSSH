class JSchAuthCancelException extends JSchException{
  String method;
  JSchAuthCancelException () {
    super();
  }
  JSchAuthCancelException (String s) {
    super(s);
    this.method=s;
  }
  public String getMethod(){
    return method;
  }
}
