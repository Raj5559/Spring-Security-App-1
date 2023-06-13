package com.demo.in.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
	
	@GetMapping(value = "/")
	public String showHomePage() {
		return "home";
	}
	
	@GetMapping(value = "/welcome")
	public String showWelcomePage() {
		return "welcome";
	}
	
	@GetMapping(value = "/admin")
	public String showAdminPage() {
		return "admin";
	}
	
	@GetMapping(value = "/employee")
	public String showEmployeePage() {
		return "employee";
	}
	
	@GetMapping(value = "/student")
	public String showStudentPage() {
		return "student";
	}
	
	@GetMapping(value = "/access-denied")
	public String showAccessDeniedPage() {
		return "access-denied";
	}

}
