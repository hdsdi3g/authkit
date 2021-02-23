package tv.hd3g.authkit.mod;

import tv.hd3g.commons.codepolicyvalidation.CheckPolicy;

class CodePolicyValidationTest extends CheckPolicy {

	@Override
	public void springBootControllersInControllerPackage() {
		/**
		 * Buggy run
		 */
	}

}
