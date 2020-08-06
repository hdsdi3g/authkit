package tv.hd3g.authkit.tool;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.springframework.test.web.servlet.ResultMatcher;

public class CheckHateoas {

	public static ResultMatcher checkHateoasPresence() {
		final var linkPresence = jsonPath("$._links").isMap();
		return ResultMatcher.matchAll(linkPresence);
	}
}
