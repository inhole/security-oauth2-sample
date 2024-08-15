package com.securityoauth2sample.dto.request;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class SignUp {
    public String email;
    public String name;
    public String password;

    @Builder
    public SignUp(String email, String name, String password) {
        this.email = email;
        this.name = name;
        this.password = password;
    }
}
