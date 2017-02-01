package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

public interface SecretRepository extends JpaRepository<NamedSecret, UUID> {
  int SECRET_BATCH_SIZE = 50;

  NamedSecret findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(String name);
  NamedSecret findOneByUuid(UUID uuid);

  List<NamedSecret> deleteByNameIgnoreCase(String name);
  List<NamedSecret> findAllByNameIgnoreCase(String name);
  Slice<NamedSecret> findByEncryptionKeyUuidNot(UUID encryptionKeyUuid, Pageable page);

  default List<String> findAllPaths(Boolean findPaths) {
    if (!findPaths) {
      return newArrayList();
    }

    return findAll().stream()
        .map(NamedSecret::getName)
        .flatMap(NamedSecret::fullHierarchyForPath)
        .distinct()
        .sorted()
        .collect(Collectors.toList());
  }

  default NamedSecret createIfNotExists(NamedSecret namedSecret){
    NamedSecret existing = findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(namedSecret.getName());
    if (existing == null){
      return saveAndFlush(namedSecret);
    }
    return existing;
  }
}
