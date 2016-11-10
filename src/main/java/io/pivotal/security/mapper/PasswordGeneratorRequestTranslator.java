package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.StringSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.google.common.collect.ImmutableSet.of;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Component
public class PasswordGeneratorRequestTranslator implements RequestTranslator<NamedPasswordSecret>, SecretGeneratorRequestTranslator<PasswordGenerationParameters, NamedPasswordSecret> {

  @Autowired
  SecretGenerator<PasswordGenerationParameters, StringSecret> stringSecretGenerator;

  @Autowired
  SecretEncryptionHelper secretEncryptionHelper;

  @Override
  public PasswordGenerationParameters validRequestParameters(DocumentContext parsed, NamedPasswordSecret entity) {
    PasswordGenerationParameters secretParameters;

    Boolean regenerate = parsed.read("$.regenerate", Boolean.class);
    if (Boolean.TRUE.equals(regenerate)) {
      List<Object> values = parsed.read("$..*");
      if (values.size() > 1) {
        throw new ParameterizedValidationException("error.invalid_regenerate_parameters");
      }
      secretParameters = secretEncryptionHelper.retrieveGenerationParameters(entity);
      if (secretParameters == null) {
        throw new ParameterizedValidationException("error.cannot_regenerate_non_generated_credentials");
      }
    } else {
      secretParameters = new PasswordGenerationParameters();
      Optional.ofNullable(parsed.read("$.parameters.length", Integer.class))
          .ifPresent(secretParameters::setLength);
      Optional.ofNullable(parsed.read("$.parameters.exclude_lower", Boolean.class))
          .ifPresent(secretParameters::setExcludeLower);
      Optional.ofNullable(parsed.read("$.parameters.exclude_upper", Boolean.class))
          .ifPresent(secretParameters::setExcludeUpper);
      Optional.ofNullable(parsed.read("$.parameters.exclude_number", Boolean.class))
          .ifPresent(secretParameters::setExcludeNumber);
      Optional.ofNullable(parsed.read("$.parameters.exclude_special", Boolean.class))
          .ifPresent(secretParameters::setExcludeSpecial);
      Optional.ofNullable(parsed.read("$.parameters.only_hex", Boolean.class))
          .ifPresent(secretParameters::setOnlyHex);

      if (!secretParameters.isValid()) {
        throw new ParameterizedValidationException("error.excludes_all_charsets");
      }
    }
    return secretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedPasswordSecret secretEntity, DocumentContext documentContext) {
    PasswordGenerationParameters requestParameters = validRequestParameters(documentContext, secretEntity);
    StringSecret secret = stringSecretGenerator.generateSecret(requestParameters);
    secretEntity.setValue(secret.getValue());
    secretEncryptionHelper.refreshEncryptedGenerationParameters(secretEntity, requestParameters);
  }

  @Override
  public Set<String> getValidKeys() {
    return of(
        "$['type']",
        "$['name']",
        "$['overwrite']",
        "$['regenerate']",
        "$['parameters']",
        "$['parameters']['length']",
        "$['parameters']['exclude_lower']",
        "$['parameters']['exclude_upper']",
        "$['parameters']['exclude_number']",
        "$['parameters']['exclude_special']",
        "$['parameters']['only_hex']"
      );
  }
}
