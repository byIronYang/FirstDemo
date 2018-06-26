package com.yang.TestDemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableAutoConfiguration
@RestController
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TestDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(TestDemoApplication.class, args);
    }

    @RequestMapping("/")
    public String demo() {
        return "hello spring boot,begin!!!";
    }

    @RequestMapping("/hello")
    public String hello() {
        return "hello spring boot";
    }

    @RequestMapping("/role")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String role() {
        return "admin ";
    }
}
