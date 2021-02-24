/*
 * This file is part of AuthKit.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * Copyright (C) hdsdi3g for hd3g.tv 2019
 *
 */
package tv.hd3g.authkit.mod.service;

import java.util.Random;

public interface CipherService {

	Random getSecureRandom();

	byte[] cipherFromString(String text);

	String unCipherToString(byte[] rawData);

	/**
	 * @param clearData will be wipe after call.
	 */
	byte[] cipherFromData(byte[] clearData);

	byte[] unCipherToData(byte[] rawData);

	String computeSHA3FromString(String text);

}
