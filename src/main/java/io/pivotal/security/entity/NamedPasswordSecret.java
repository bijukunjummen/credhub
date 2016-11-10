package io.pivotal.security.entity;

import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.view.SecretKind;

import javax.naming.OperationNotSupportedException;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_BYTES;

@Entity
@Table(name = "PasswordSecret")
@DiscriminatorValue("password")
public class NamedPasswordSecret extends NamedStringSecret<NamedPasswordSecret> {

  @Column(length = 255 + NONCE_BYTES)
  private byte[] encryptedGenerationParameters;

  @Column(length = NONCE_BYTES)
  private byte[] parametersNonce;

  @SuppressWarnings("unused")
  public NamedPasswordSecret() {
  }

  public NamedPasswordSecret(String name) {
    super(name);
  }

  public NamedPasswordSecret(String name, String value) {
    super(name, value);
  }

  public byte[] getEncryptedGenerationParameters() {
    return encryptedGenerationParameters;
  }

  public NamedPasswordSecret setEncryptedGenerationParameters(byte[] encryptedGenerationParameters) {
    this.encryptedGenerationParameters = encryptedGenerationParameters;
    return this;
  }

  public byte[] getParametersNonce() {
    return parametersNonce;
  }

  public NamedPasswordSecret setParametersNonce(byte[] parametersNonce) {
    this.parametersNonce = parametersNonce;
    return this;
  }

  @Override
  public String getSecretType() {
    return "password";
  }

  @Override
  void copyIntoImpl(NamedPasswordSecret copy) {
    copy.setEncryptedGenerationParameters(encryptedGenerationParameters);
    copy.setParametersNonce(parametersNonce);
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.PASSWORD;
  }
}
