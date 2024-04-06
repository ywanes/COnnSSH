class ExceptionAuthCancel extends ExceptionCOnn{
  String method;
  ExceptionAuthCancel () {
    super();
  }
  ExceptionAuthCancel (String s) {
    super(s);
    this.method=s;
  }
  public String getMethod(){
    return method;
  }
}
