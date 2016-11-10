package io.pivotal.security.entity;

// todo GROT
public class SecretEncryptionHelperProvider {
  public static SecretEncryptionHelper getInstance() {
    return BeanStaticProvider.getInstance(SecretEncryptionHelper.class);
  }
}
