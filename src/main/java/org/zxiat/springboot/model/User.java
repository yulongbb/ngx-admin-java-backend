package org.zxiat.springboot.model;

import lombok.*;
import lombok.extern.java.Log;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;


import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Data
@Log
@RequiredArgsConstructor
@Document(collection = "users")
public class User {

    @Id
    private String id;

    @NotBlank
    @Size(max = 20)
    private final String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private final String email;

    @NotBlank
    @Size(max = 120)
    private final String password;

    @DBRef
    private Set<Role> roles = new HashSet<>();
}
