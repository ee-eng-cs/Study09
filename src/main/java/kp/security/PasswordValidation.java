package kp.security;

import java.util.regex.Pattern;

/**
 * Password validation.
 *
 */
public class PasswordValidation {

	/**
	 * Validates password strength.
	 * 
	 */
	public static void launch() {

		final Pattern pattern = Pattern.compile("(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8}");
		System.out.printf("Password validation pattern[%s]%n", pattern);
		for (String password : new String[] { "Passw0rd", "Passw0r", "Password", "passw0rd", "PASSW0RD" }) {
			boolean matched = pattern.matcher(password).find();
			System.out.printf("matched[%5b], password[%s]%n", matched, password);
		}
		System.out.println("- ".repeat(50));
	}
}