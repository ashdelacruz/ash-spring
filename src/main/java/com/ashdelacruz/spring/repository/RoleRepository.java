package com.ashdelacruz.spring.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.models.mongodb.collections.Role;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);

    Boolean existsByName(ERole name);
}