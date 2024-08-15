package com.securityoauth2sample.domain;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String email;

    private String password;

    private String profile;

    private MemberRole memberRole;

    @Builder
    public Member(String name, String email, String password, String profile, MemberRole memberRole, String memberKey) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.profile = profile;
        this.memberRole = memberRole;
    }
}
