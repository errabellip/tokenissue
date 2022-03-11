package com.errabelli.token.service.model;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

/**
 * Simple placeholder for holding user info extracted from the JWT
 * 
 * @author uisr96
 *
 */
public class UserProfileTo {


    private String username;

    private String role;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

	@Override
	public String toString() {
		ReflectionToStringBuilder builder = new ReflectionToStringBuilder(this);
		builder.append("username", username);
		builder.append("role", role);
		return builder.toString();
	}

	
    
    
}