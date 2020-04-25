package com.bestaone.hiauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@ComponentScan({"com.bestaone.hiauth"})
@SpringBootApplication
@EnableTransactionManagement
public class HiAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(HiAuthApplication.class, args);
    }

}