package io.pivotal.security.controller.v1;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class PermissionsControllerAuditLogTest {

  public static final CredentialName CRED1 = new CredentialName("/cred1");

  @Autowired
  private WebApplicationContext applicationContext;

  @MockBean
  private EventAuditRecordDataService eventAuditRecordDataService;

  @MockBean
  private PermissionsDataService permissionsDataService;

  @MockBean
  private CredentialNameRepository credentialNameRepository;

  @MockBean
  private PermissionService permissionService;

  private MockMvc mockMvc;

  @Before
  public void setUp() throws Exception {
    mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
      .apply(springSecurity())
      .build();
    PermissionEntry ace = new PermissionEntry(
        "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
        Arrays.asList(READ_ACL));
    when(permissionsDataService.getAccessControlList(eq(CRED1)))
        .thenReturn(Arrays.asList(ace));
    when(permissionService.hasPermission(any(), anyString(), eq(READ_ACL)))
        .thenReturn(true);
    when(credentialNameRepository.findOneByNameIgnoreCase(CRED1.getName())).thenReturn(CRED1);
    reset(eventAuditRecordDataService);
  }

  @Test
  public void whenGettingAPermission_itLogsTheRetrieval() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/permissions?credential_name=" + CRED1.getName())
      .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    this.mockMvc.perform(get)
      .andExpect(status().isOk());

    ArgumentCaptor<List> recordCaptor = ArgumentCaptor
      .forClass(List.class);
    verify(eventAuditRecordDataService).save(recordCaptor.capture());

    EventAuditRecord auditRecord = (EventAuditRecord) recordCaptor.getValue().get(0);

    assertThat(auditRecord.getCredentialName(), equalTo(CRED1.getName()));
    assertThat(auditRecord.getOperation(), equalTo(ACL_ACCESS.toString()));
  }
}
