package com.ashdelacruz.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class SpringAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringAuthServiceApplication.class, args);
	}

}
