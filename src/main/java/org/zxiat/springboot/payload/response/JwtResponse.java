package org.zxiat.springboot.payload.response;

import lombok.*;

@Data
@RequiredArgsConstructor
@AllArgsConstructor
public class JwtResponse {
    private String token;
}
