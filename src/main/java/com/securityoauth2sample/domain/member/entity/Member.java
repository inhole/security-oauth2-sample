package com.securityoauth2sample.domain.member.entity;

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

    private String memberKey;

    @Builder
    public Member(String name, String email, String profile, MemberRole memberRole, String memberKey) {
        this.name = name;
        this.email = email;
        this.profile = profile;
        this.memberRole = memberRole;
        this.memberKey = memberKey;
    }
}
