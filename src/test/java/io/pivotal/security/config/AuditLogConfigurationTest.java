package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.service.DatabaseAuditLogService;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "AuditLogConfigurationTest", "NoExpirationSymmetricKeySecurityConfiguration"})
public class AuditLogConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  @InjectMocks
  DatabaseAuditLogService auditLogService;

  @Mock
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  Filter springSecurityFilterChain;

  private MockMvc mockMvc;
  private String credentialUrlPath;
  private String caUrlPath1;
  private String caUrlPath2;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
      credentialUrlPath = "/api/v1/data/foo";
      caUrlPath1 = "/api/v1/ca/bar";
      caUrlPath2 = "/api/v1/ca/baz";
    });

    describe("when a request to set credential is served", () -> {

      beforeEach(() -> {
        MockHttpServletRequestBuilder set = put(credentialUrlPath)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .content("{\"type\":\"value\",\"value\":\"password\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential update operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getOperation(), equalTo("credential_update"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to generate a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder post = post(credentialUrlPath)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"password\"}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(post)
            .andExpect(status().isOk());
      });

      it("logs an audit record for credential_update operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getOperation(), equalTo("credential_update"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to delete a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder delete = delete(credentialUrlPath)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"value\"}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(delete)
            .andExpect(status().is4xxClientError());
      });

      it("logs an audit record for credential_delete operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getOperation(), equalTo("credential_delete"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to retrieve a credential is served", () -> {
      beforeEach(() -> {
        doUnsuccessfulFetch(credentialUrlPath);
      });

      it("logs an audit record for credential_access operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request to set or generate a credential is served", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder set = put(caUrlPath1)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"root\",\"value\":{\"certificate\":\"my_cert\",\"private_key\":\"private_key\"}}")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());

        MockHttpServletRequestBuilder generate = post(caUrlPath2)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .content("{\"type\":\"root\",\"parameters\":{\"common_name\":\"baz.com\"}}")
            .header("X-Forwarded-For", "3.3.3.3,4.4.4.4")
            .with(request -> {
              request.setRemoteAddr("12345");
              return request;
            });

        mockMvc.perform(generate)
            .andExpect(status().isOk());
      });

      it("logs an audit record for ca_update operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(2)).save(recordCaptor.capture());

        List<OperationAuditRecord> records = recordCaptor.getAllValues();

        assertThat(records.size(), equalTo(2));

        OperationAuditRecord auditRecord1 = records.get(0);
        assertThat(auditRecord1.getPath(), equalTo(caUrlPath1));
        assertThat(auditRecord1.getOperation(), equalTo("ca_update"));
        assertThat(auditRecord1.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord1.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));

        OperationAuditRecord auditRecord2 = records.get(1);
        assertThat(auditRecord2.getPath(), equalTo(caUrlPath2));
        assertThat(auditRecord2.getOperation(), equalTo("ca_update"));
        assertThat(auditRecord2.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord2.getXForwardedFor(), equalTo("3.3.3.3,4.4.4.4"));
      });
    });

    describe("when a request to retrieve a CA is served", () -> {
      beforeEach(() -> {
        doUnsuccessfulFetch(caUrlPath1);
      });

      it("logs an audit record for ca_access operation", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getPath(), equalTo(caUrlPath1));
        assertThat(auditRecord.getOperation(), equalTo("ca_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12345"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
      });
    });

    describe("when a request has multiple X-Forwarded-For headers set", () -> {
      beforeEach(() -> {
        MockHttpServletRequestBuilder set = put(credentialUrlPath)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .header("X-Forwarded-For", "3.3.3.3")
            .content("{\"type\":\"value\",\"value\":\"password\"}")
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });

        mockMvc.perform(set)
            .andExpect(status().isOk());
      });

      it("logs all X-Forwarded-For values", () -> {
        ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor.forClass(OperationAuditRecord.class);

        verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

        OperationAuditRecord auditRecord = recordCaptor.getValue();

        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2,3.3.3.3"));
      });
    });
  }

  private void doUnsuccessfulFetch(String urlPath) throws Exception {
    MockHttpServletRequestBuilder get = get(urlPath)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT)
        .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
        .with(request -> {
          request.setRemoteAddr("12345");
          return request;
        });

    mockMvc.perform(get)
        .andExpect(status().is4xxClientError());
  }
}
