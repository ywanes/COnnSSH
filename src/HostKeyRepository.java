public interface HostKeyRepository{
  final int OK=0;
  final int NOT_INCLUDED=1;
  final int CHANGED=2;

  /**
   * Checks if <code>host</code> is included with the <code>key</code>. 
   * 
   * @return #NOT_INCLUDED, #OK or #CHANGED
   * @see #NOT_INCLUDED
   * @see #OK
   * @see #CHANGED
   */
  int check(String host, byte[] key);

  /**
   * Adds a host key <code>hostkey</code>
   *
   * @param hostkey a host key to be added
   * @param ui a user interface for showing messages or promping inputs.
   * @see UserInfo
   */
  void add(HostKey hostkey, UserInfo ui);

  /**
   * Removes a host key if there exists mached key with
   * <code>host</code>, <code>type</code>.
   *
   * @see #remove(String host, String type, byte[] key)
   */
  void remove(String host, String type);

  /**
   * Removes a host key if there exists a matched key with
   * <code>host</code>, <code>type</code> and <code>key</code>.
   */
  void remove(String host, String type, byte[] key);

  /**
   * Returns id of this repository.
   *
   * @return identity in String
   */
  String getKnownHostsRepositoryID();

  /**
   * Retuns a list for host keys managed in this repository.
   *
   * @see #getHostKey(String host, String type)
   */
  HostKey[] getHostKey();

  /**
   * Retuns a list for host keys managed in this repository.
   *
   * @param host a hostname used in searching host keys.
   *        If <code>null</code> is given, every host key will be listed.
   * @param type a key type used in searching host keys,
   *        and it should be "ssh-dss" or "ssh-rsa".
   *        If <code>null</code> is given, a key type type will not be ignored.
   */
  HostKey[] getHostKey(String host, String type);
}
