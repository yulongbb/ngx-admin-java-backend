package org.zxiat.springboot.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.zxiat.springboot.model.ERole;
import org.zxiat.springboot.model.Role;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}
