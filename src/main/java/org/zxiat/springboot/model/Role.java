package org.zxiat.springboot.model;

import lombok.Data;
import lombok.extern.java.Log;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Log
@Document(collection = "roles")
public class Role {

    @Id
    private String id;

    private ERole name;

}
