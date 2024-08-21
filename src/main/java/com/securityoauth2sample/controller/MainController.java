package com.securityoauth2sample.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MainController {

    @GetMapping("/oauth2")
    public String oauth2() {
        return "oauth2.html";
    }
}
