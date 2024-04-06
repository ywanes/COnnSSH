class ExceptionPartialAuth extends ExceptionCOnn{
  String methods;
  public ExceptionPartialAuth () {
    super();
  }
  public ExceptionPartialAuth (String s) {
    super(s);
    this.methods=s;
  }
  public String getMethods(){
    return methods;
  }
}
