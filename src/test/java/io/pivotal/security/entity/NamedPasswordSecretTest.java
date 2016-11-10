package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedPasswordSecretTest {

  @Autowired
  SecretDataService secretDataService;

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  SecretEncryptionHelper secretEncryptionHelper;

  NamedPasswordSecret subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedPasswordSecret("Foo");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    it("returns type password", () -> {
      assertThat(subject.getSecretType(), equalTo("password"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedPasswordSecret("foo");
      });

      it("updates the secret value with the same name when overwritten", () -> {
        subject.setValue("my-value1");
        subject = (NamedPasswordSecret) secretDataService.save(subject);
        byte[] firstNonce = subject.getNonce();

        subject.setValue("my-value2");
        subject = (NamedPasswordSecret) secretDataService.save(subject);

        NamedPasswordSecret second = (NamedPasswordSecret) secretDataService.findByUuid(subject.getUuid().toString());
        assertThat(second.getValue(), equalTo("my-value2"));
        assertThat(Arrays.equals(firstNonce, second.getNonce()), is(false));
      });

      it("only encrypts the value once for the same secret", () -> {
        subject.setValue("my-value");
        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));

        subject.setValue("my-value");
        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
      });

      it("sets the nonce and the encrypted value", () -> {
        subject.setValue("my-value");
        assertThat(subject.getEncryptedValue(), notNullValue());
        assertThat(subject.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setValue("my-value");
        assertThat(subject.getValue(), equalTo("my-value"));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setValue(null);
      });

      it("sets UUID when Hibernate stores the object", () -> {
        subject.setValue("my-value");
        secretDataService.save(subject);
        assertThat(subject.getUuid().toString().length(), equalTo(36));
      });
    });

    describe("#copyInto", () -> {
      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();

        PasswordGenerationParameters parameters = new PasswordGenerationParameters();
        parameters.setExcludeNumber(true);
        parameters.setExcludeLower(true);
        parameters.setExcludeUpper(false);

        subject = new NamedPasswordSecret("foo", "value");
        secretEncryptionHelper.refreshEncryptedGenerationParameters(subject, parameters);
        subject.setUuid(uuid);
        subject.setUpdatedAt(frozenTime);

        NamedPasswordSecret copy = new NamedPasswordSecret();
        subject.copyInto(copy);

        PasswordGenerationParameters copyParameters = secretEncryptionHelper.retrieveGenerationParameters(copy);

        assertThat(copy.getName(), equalTo("foo"));
        assertThat(copy.getValue(), equalTo("value"));
        assertThat(copyParameters.isExcludeNumber(), equalTo(true));
        assertThat(copyParameters.isExcludeLower(), equalTo(true));
        assertThat(copyParameters.isExcludeUpper(), equalTo(false));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getUpdatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
