package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.cleanUpAfterTests;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class SecretEncryptionHelperTest {

  @Autowired
  SecretEncryptionHelper subject;

  @Autowired
  EncryptionService encryptionService;

  private PasswordGenerationParameters generationParameters;

  {
    wireAndUnwire(this);
    cleanUpAfterTests(this);

    beforeEach(() -> {
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });


    describe("#refreshEncryptedValue", () -> {
      it("encrypts a private key and updates the EncryptedValueContainer", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

        subject.refreshEncryptedValue(valueContainer, "some fake secret");

        assertNotNull(valueContainer.getEncryptedValue());
        assertNotNull(valueContainer.getNonce());
      });

      it("only encrypts a given value one time", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

        subject.refreshEncryptedValue(valueContainer, "some fake secret");
        subject.refreshEncryptedValue(valueContainer, "some fake secret");

        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
      });

      it("does not error on null values", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");
        subject.refreshEncryptedValue(valueContainer, null);
        assertThat(valueContainer.getNonce(), equalTo(null));
        assertThat(valueContainer.getEncryptedValue(), equalTo(null));
      });
    });

    describe("#retrieveClearTextValue", () -> {
      it("can get the clear text from a valueContainer", () -> {
        NamedCertificateAuthority valueContainer = new NamedCertificateAuthority("my-ca");

        subject.refreshEncryptedValue(valueContainer, "some fake secret");
        String clearTextValue = subject.retrieveClearTextValue(valueContainer);

        assertThat(clearTextValue, equalTo("some fake secret"));
      });
    });

    describe("#getGenerationParameters", () -> {
      beforeEach(() -> {
        generationParameters = new PasswordGenerationParameters()
            .setExcludeLower(true)
            .setExcludeSpecial(true)
            .setLength(10);
      });

      it("only encrypts the generationParameters once for the same secret parameters", () -> {
        NamedPasswordSecret passwordSecret = new NamedPasswordSecret("my-password");
        subject.refreshEncryptedGenerationParameters(passwordSecret, generationParameters);
        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));

        PasswordGenerationParameters generationParameters2 = new PasswordGenerationParameters()
            .setExcludeLower(true)
            .setExcludeSpecial(true)
            .setLength(10);
        subject.refreshEncryptedGenerationParameters(passwordSecret, generationParameters2);
        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
      });

      it("sets the parametersNonce and the encryptedGenerationParameters", () -> {
        NamedPasswordSecret passwordSecret = new NamedPasswordSecret("my-password", "password");
        subject.refreshEncryptedGenerationParameters(passwordSecret, generationParameters);
        assertThat(subject.retrieveGenerationParameters(passwordSecret), notNullValue());
        assertThat(passwordSecret.getParametersNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        NamedPasswordSecret passwordSecret = new NamedPasswordSecret("my-password", "length10pw");

        subject.refreshEncryptedGenerationParameters(passwordSecret, generationParameters);

        PasswordGenerationParameters retrievedGenerationParameters = subject.retrieveGenerationParameters(passwordSecret);
        assertThat(retrievedGenerationParameters.getLength(), equalTo(10));
        assertThat(retrievedGenerationParameters.isExcludeLower(), equalTo(true));
        assertThat(retrievedGenerationParameters.isExcludeUpper(), equalTo(false));
      });
    });
  }
}
