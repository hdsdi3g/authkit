package tv.hd3g.authkit.mod;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.tool.DataGenerator;

class AuthKitExceptionTest {

	private AuthKitException authKitException;
	private int returnCode;
	private String message;

	@BeforeEach
	public void init() {
		message = makeRandomString();
		returnCode = DataGenerator.random.nextInt(1000);
		authKitException = new AuthKitException(returnCode, message);
	}

	@Test
	void testAuthKitException() {
		authKitException = new AuthKitException(message);
		assertEquals(message, authKitException.getMessage());
		assertEquals(SC_BAD_REQUEST, authKitException.getReturnCode());
	}

	@Test
	void testGetMessage() {
		assertEquals(message, authKitException.getMessage());
	}

	@Test
	void testGetReturnCode() {
		assertEquals(returnCode, authKitException.getReturnCode());
	}

}
