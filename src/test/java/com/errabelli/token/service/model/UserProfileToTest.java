package com.suntrust.token.service.model;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class UserProfileToTest {

	@Test
	public void testUserprofileTo(){
		
		UserProfileTo userProfileTo = new UserProfileTo();
		String userName = "testuserName";
		String role = "testRole";
		userProfileTo.setUsername(userName);
		userProfileTo.setRole(role);
		assertEquals(userProfileTo.getUsername(), userName);
		assertEquals(userProfileTo.getRole(), role);
		UserProfileTo cloneUserProfileTo = userProfileTo;
		assertEquals(userProfileTo.toString(), cloneUserProfileTo.toString());
		
	}
}

