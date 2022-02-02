package org.zxiat.springboot.payload.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class ResetPasswordDTO {
    @NotBlank
    private String password;

    @NotBlank
    private String confirmPassword;
}
