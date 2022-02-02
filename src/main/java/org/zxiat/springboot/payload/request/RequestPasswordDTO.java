package org.zxiat.springboot.payload.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class RequestPasswordDTO {
    @NotBlank
    private String email;
}
