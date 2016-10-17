package io.pivotal.security.controller.v1;

import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class CertificateSecretParameters implements RequestParameters {
  // Required Certificate Parameters
  private String organization;
  private String state;
  private String country;

  // Optional Certificate Parameters
  private String commonName;
  private String organizationUnit;
  private String locality;
  private String[] alternativeNames = new String[0];
  private int keyLength = 2048;
  private int durationDays = 365;
  private String ca;
  private String type;
  private X500Name x500Name;

  public CertificateSecretParameters() {
  }

  public CertificateSecretParameters(String certificate) {
    try {
      this.x500Name = getSubjectX500Name(certificate);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public CertificateSecretParameters setCommonName(String commonName) {
    this.commonName = commonName;
    return this;
  }

  public CertificateSecretParameters setOrganization(String organization) {
    this.organization = organization;
    return this;
  }

  public CertificateSecretParameters setOrganizationUnit(String organizationUnit) {
    this.organizationUnit = organizationUnit;
    return this;
  }

  public CertificateSecretParameters setLocality(String locality) {
    this.locality = locality;
    return this;
  }

  public CertificateSecretParameters setState(String state) {
    this.state = state;
    return this;
  }

  public CertificateSecretParameters setCountry(String country) {
    this.country = country;
    return this;
  }

  public void validate() {
    if (StringUtils.isEmpty(organization)
        && StringUtils.isEmpty(state)
        && StringUtils.isEmpty(locality)
        && StringUtils.isEmpty(organizationUnit)
        && StringUtils.isEmpty(commonName)
        && StringUtils.isEmpty(country)) {
      throw new ParameterizedValidationException("error.missing_certificate_parameters");
    }

    switch (keyLength) {
      case 2048:
      case 3072:
      case 4096:
        break;
      default:
        throw new ParameterizedValidationException("error.invalid_key_length");
    }

    if (durationDays < 1 || durationDays > 3650) {
      throw new ParameterizedValidationException("error.invalid_duration");
    }
  }

  public X500Name getDN() {
    if (this.x500Name != null) {
      return this.x500Name;
    }

    X500NameBuilder builder = new X500NameBuilder();

    if (!StringUtils.isEmpty(organization)) {
      builder.addRDN(BCStyle.O, organization);
    }
    if (!StringUtils.isEmpty(state)) {
      builder.addRDN(BCStyle.ST, state);
    }
    if (!StringUtils.isEmpty(country)) {
      builder.addRDN(BCStyle.C, country);
    }
    if (!StringUtils.isEmpty(commonName)) {
      builder.addRDN(BCStyle.CN, commonName);
    }
    if (!StringUtils.isEmpty(organizationUnit)) {
      builder.addRDN(BCStyle.OU, organizationUnit);
    }
    if (!StringUtils.isEmpty(locality)) {
      builder.addRDN(BCStyle.L, locality);
    }

    return builder.build();
  }

  public CertificateSecretParameters addAlternativeName(String alternativeName) {
    List<String> tmp = new ArrayList<>(Arrays.asList(alternativeNames));
    tmp.add(alternativeName);
    alternativeNames = tmp.toArray(new String[tmp.size()]);
    return this;
  }

  public CertificateSecretParameters addAlternativeNames(String[] alternativeNames) {
    for (String a : alternativeNames) {
      addAlternativeName(a);
    }
    return this;
  }

  public List<String> getAlternativeNames() {
    return Arrays.asList(alternativeNames);
  }

  public CertificateSecretParameters setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    return this;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public CertificateSecretParameters setDurationDays(int durationDays) {
    this.durationDays = durationDays;
    return this;
  }

  public int getDurationDays() {
    return durationDays;
  }

  public String getCa() {
    return ca;
  }

  public CertificateSecretParameters setCa(String ca) {
    this.ca = ca;
    return this;
  }

  public String getType() {
    return type;
  }

  public CertificateSecretParameters setType(String type) {
    this.type = type;
    return this;
  }

  public X500Name getX500Name() {
    return x500Name;
  }

  private static X500Name getSubjectX500Name(String cert) throws IOException, CertificateException, NoSuchProviderException {
    X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
        .generateCertificate(new ByteArrayInputStream(cert.getBytes()));
    return new X500Name(certificate.getSubjectDN().getName());
  }
}
