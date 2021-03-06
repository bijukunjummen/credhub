package io.pivotal.security.controller.v1.credential;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.generator.PassayStringCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialsControllerRegenerateTest {

  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private CredentialDataService credentialDataService;

  @MockBean
  private PassayStringCredentialGenerator passwordGenerator;

  @MockBean
  private SshGenerator sshGenerator;

  @MockBean
  private RsaGenerator rsaGenerator;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;
  private Consumer<Long> fakeTimeSetter;

  @Before
  public void beforeEach() {
    fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void regeneratingAPassword_regeneratesThePassword_andPersistsAnAuditEntry() throws Exception {
    UUID uuid = UUID.randomUUID();

    when(passwordGenerator.generateCredential(any(StringGenerationParameters.class)))
        .thenReturn(new StringCredentialValue("generated-credential"));
    PasswordCredential originalCredential = new PasswordCredential("my-password");
    originalCredential.setEncryptor(encryptor);
    StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeNumber(true);
    originalCredential
        .setPasswordAndGenerationParameters("original-password", generationParameters);
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    doReturn(originalCredential).when(credentialDataService).findMostRecent("my-password");

    doAnswer(invocation -> {
      PasswordCredential newCredential = invocation.getArgumentAt(0, PasswordCredential.class);
      newCredential.setUuid(uuid);
      newCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(10));
      return newCredential;
    }).when(credentialDataService).save(any(PasswordCredential.class));

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.type").value("password"))
        .andExpect(jsonPath("$.id").value(uuid.toString()))
        .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    ArgumentCaptor<PasswordCredential> argumentCaptor = ArgumentCaptor
        .forClass(PasswordCredential.class);
    verify(credentialDataService, times(1)).save(argumentCaptor.capture());

    PasswordCredential newPassword = argumentCaptor.getValue();

    assertThat(newPassword.getPassword(), equalTo("generated-credential"));
    assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-password", "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200);
  }

  @Test
  public void regeneratingAnRsaKey_regeneratesTheRsaKey_andPersistsAnAuditEntry() throws Exception {
    UUID uuid = UUID.randomUUID();

    when(rsaGenerator.generateCredential(any(RsaGenerationParameters.class)))
        .thenReturn(new RsaCredentialValue("public_key", "private_key"));
    RsaCredential originalCredential = new RsaCredential("my-rsa");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    doReturn(originalCredential).when(credentialDataService).findMostRecent("my-rsa");

    doAnswer(invocation -> {
      RsaCredential newCredential = invocation.getArgumentAt(0, RsaCredential.class);
      newCredential.setUuid(uuid);
      newCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(10));
      return newCredential;
    }).when(credentialDataService).save(any(RsaCredential.class));

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"regenerate\":true,\"name\":\"my-rsa\"}");

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.type").value("rsa"))
        .andExpect(jsonPath("$.id").value(uuid.toString()))
        .andExpect(
            jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    ArgumentCaptor<RsaCredential> argumentCaptor = ArgumentCaptor
        .forClass(RsaCredential.class);
    verify(credentialDataService, times(1)).save(argumentCaptor.capture());

    RsaCredential newRsa = argumentCaptor.getValue();

    assertThat(newRsa.getPrivateKey(), equalTo("private_key"));
    assertThat(newRsa.getPublicKey(), equalTo("public_key"));

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-rsa", "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200);
  }

  @Test
  public void regeneratingAnSshKey_regeneratesTheSshKey_andPersistsAnAuditEntry() throws Exception {
    UUID uuid = UUID.randomUUID();

    when(sshGenerator.generateCredential(any(SshGenerationParameters.class)))
        .thenReturn(new SshCredentialValue("public_key", "private_key", null));
    SshCredential originalCredential = new SshCredential("my-ssh");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    doReturn(originalCredential).when(credentialDataService).findMostRecent("my-ssh");

    doAnswer(invocation -> {
      SshCredential newCredential = invocation.getArgumentAt(0, SshCredential.class);
      newCredential.setUuid(uuid);
      newCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(10));
      return newCredential;
    }).when(credentialDataService).save(any(SshCredential.class));

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"regenerate\":true,\"name\":\"my-ssh\"}");

    mockMvc.perform(request)
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
        .andExpect(jsonPath("$.type").value("ssh"))
        .andExpect(jsonPath("$.id").value(uuid.toString()))
        .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    ArgumentCaptor<SshCredential> argumentCaptor = ArgumentCaptor
        .forClass(SshCredential.class);
    verify(credentialDataService, times(1)).save(argumentCaptor.capture());

    SshCredential newSsh = argumentCaptor.getValue();

    assertThat(newSsh.getPrivateKey(), equalTo("private_key"));
    assertThat(newSsh.getPublicKey(), equalTo("public_key"));

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-ssh", "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200);
  }

  @Test
  public void regeneratingACredentialThatDoesNotExist_returnsAnError_andPersistsAnAuditEntry() throws Exception {
    doReturn(null).when(credentialDataService).findMostRecent("my-password");

    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    String notFoundJson = "{" +
        "  \"error\": \"The request could not be completed because the credential does not exist or you do not have sufficient authorization.\"" +
        "}";

    mockMvc.perform(request)
        .andExpect(status().isNotFound())
        .andExpect(content().json(notFoundJson));

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-password", "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 404);
  }

  @Test
  public void regeneratingANonGeneratedPassword_returnsAnError_andPersistsAnAuditEntry() throws Exception {
    PasswordCredential originalCredential = new PasswordCredential("my-password");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setPasswordAndGenerationParameters("abcde", null);
    doReturn(originalCredential).when(credentialDataService).findMostRecent("my-password");

    String cannotRegenerateJson = "{" +
        "  \"error\": \"The password could not be regenerated because the value was " +
        "statically set. Only generated passwords may be regenerated.\"" +
        "}";

    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    mockMvc.perform(request)
        .andExpect(content().json(cannotRegenerateJson));

    auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-password", "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 400);
  }

  @Test
  public void regeneratingAPasswordWithParametersThatCannotBeDecrypted_returnsAnError() throws Exception {
    PasswordCredentialData passwordCredentialData = new PasswordCredentialData(
        "my-password");
    PasswordCredential originalCredential = new PasswordCredential(passwordCredentialData);
    originalCredential.setEncryptor(encryptor);
    originalCredential
        .setPasswordAndGenerationParameters("abcde", new StringGenerationParameters());

    passwordCredentialData.setEncryptionKeyUuid(UUID.randomUUID());
    doReturn(originalCredential).when(credentialDataService).findMostRecent("my-password");

    // language=JSON
    String cannotRegenerate = "{\n" +
        "  \"error\": \"The credential could not be accessed with the provided encryption keys. You must update your deployment configuration to continue.\"\n" +
        "}";

    MockHttpServletRequestBuilder request = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    mockMvc.perform(request)
        .andDo(print())
        .andExpect(status().isInternalServerError())
        .andExpect(content().json(cannotRegenerate));
  }
}
