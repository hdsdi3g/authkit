/*
 * The MIT License
 *
 * Copyright (c) 2013 Edin Dazdarevic (edin.dazdarevic@gmail.com)
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Edited by hdsdi3g for Authkit
 *
 */
package tv.hd3g.authkit.utility;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class CIDRUtils {

	private final InetAddress inetAddress;
	private final InetAddress startAddress;
	private final InetAddress endAddress;
	private final int prefixLength;

	/**
	 * @param cidr like 192.168.1.0/24
	 */
	public CIDRUtils(final String cidr) throws UnknownHostException {
		if (cidr.contains("/") == false) {
			throw new IllegalArgumentException("Missing CIDR: " + cidr);
		}
		final int index = cidr.indexOf('/');
		if (cidr.lastIndexOf('/') != index) {
			throw new IllegalArgumentException("Invalid IP/CIDR format: " + cidr);
		}

		inetAddress = InetAddress.getByName(cidr.substring(0, index));
		prefixLength = Integer.parseInt(cidr.substring(index + 1));

		if (prefixLength < 0) {
			throw new IllegalArgumentException("Negative CIDR: " + cidr);
		}

		ByteBuffer maskBuffer;
		int targetSize;
		if (inetAddress.getAddress().length == 4) {
			maskBuffer = ByteBuffer.allocate(4).putInt(-1);
			targetSize = 4;
		} else {
			maskBuffer = ByteBuffer.allocate(16).putLong(-1L).putLong(-1L);
			targetSize = 16;
		}

		if (prefixLength > targetSize * 8) {
			throw new IllegalArgumentException("Too big CIDR: " + cidr);
		}

		final BigInteger mask = new BigInteger(1, maskBuffer.array()).not().shiftRight(prefixLength);

		final ByteBuffer buffer = ByteBuffer.wrap(inetAddress.getAddress());
		final BigInteger ipVal = new BigInteger(1, buffer.array());

		final BigInteger startIp = ipVal.and(mask);
		final BigInteger endIp = startIp.add(mask.not());

		final byte[] startIpArr = toBytes(startIp.toByteArray(), targetSize);
		final byte[] endIpArr = toBytes(endIp.toByteArray(), targetSize);

		startAddress = InetAddress.getByAddress(startIpArr);
		endAddress = InetAddress.getByAddress(endIpArr);
	}

	/**
	 * Example for 192.168.1.0/24:
	 * @param addr 192.168.1.0
	 * @param cidr 24
	 */
	public CIDRUtils(final InetAddress addr, final int cidr) throws UnknownHostException {
		this(addr.getHostAddress() + "/" + cidr);
	}

	private byte[] toBytes(final byte[] array, final int targetSize) {
		int counter = 0;
		final List<Byte> newArr = new ArrayList<>();
		while (counter < targetSize && array.length - 1 - counter >= 0) {
			newArr.add(0, array[array.length - 1 - counter]);
			counter++;
		}

		final int size = newArr.size();
		for (int i = 0; i < targetSize - size; i++) {

			newArr.add(0, (byte) 0);
		}

		final byte[] ret = new byte[newArr.size()];
		for (int i = 0; i < newArr.size(); i++) {
			ret[i] = newArr.get(i);
		}
		return ret;
	}

	public String getNetworkAddress() {
		return startAddress.getHostAddress();
	}

	public String getBroadcastAddress() {
		return endAddress.getHostAddress();
	}

	public boolean isInRange(final String ipAddress) throws UnknownHostException {
		return isInRange(InetAddress.getByName(ipAddress));
	}

	public boolean isInRange(final InetAddress address) {
		final BigInteger start = new BigInteger(1, startAddress.getAddress());
		final BigInteger end = new BigInteger(1, endAddress.getAddress());
		final BigInteger target = new BigInteger(1, address.getAddress());
		return start.compareTo(target) <= 0 && target.compareTo(end) <= 0;
	}

	@Override
	public String toString() {
		if (startAddress.equals(endAddress)) {
			return startAddress.getHostAddress();
		}
		return startAddress.getHostAddress() + "/" + endAddress.getHostAddress();
	}
}
