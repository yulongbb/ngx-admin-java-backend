package org.zxiat.springboot.repository;


import org.springframework.data.mongodb.repository.MongoRepository;
import org.zxiat.springboot.model.User;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
}