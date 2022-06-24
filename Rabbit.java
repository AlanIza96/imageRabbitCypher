/**
 * @see {@link http://tools.ietf.org/rfc/rfc4503.txt}
 */
public class Rabbit {
	private static final int[] A = new int[] { 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3 };
	private static final long MAX_UNSIGNED_INT = Integer.MAX_VALUE * 2l + 2; //2^32
	private static final boolean DEBUG = false;

	private int[] X;
	private int[] C;
	private byte b;

	private byte[] keyStream;
	private int keyIndex;

	public Rabbit() {
		reset();
	}

	public void reset() {
		b = 0;
		X = new int[8];
		C = new int[8];

		keyStream = null;
		keyIndex = 0;
	}

	public byte[] crypt(byte[] data) {
		byte[] result = new byte[data.length];

		for (int i = 0; i < data.length; i++) {
			if (keyStream == null || keyIndex == 16) {
				extractKeyStream();
				keyIndex = 0;

				if (DEBUG) {
					System.out.println("Key Stream:");
					for (byte k : keyStream) {
						System.out.print(Integer.toHexString(Byte.toUnsignedInt(k)) + " ");
					}
					System.out.println();
				}
			}
			result[i] = (byte) ((data[i] ^ keyStream[keyIndex++]) & 0xff);
		}
		return result;
	}

	public void extractKeyStream() {
		nextState();
		keyStream = new byte[16];

		int temp;

		for (int j = 0; j < 8; j++) {
			if (j%2 == 0) {
				temp = ((X[6-j] >> 16) & 0xFFFF) ^ (X[(9-j) % 8] & 0xFFFF);
			}
			else {
				temp = (X[7-j] & 0xFFFF) ^ ((X[(12-j) % 8] >> 16) & 0xFFFF);
			}
			keyStream[2*j]		= (byte)((temp >> 8) & 0xFF);
			keyStream[2*j + 1]	= (byte)(temp & 0xFF);
		}
	}

	public void setupKey(byte[] input) {
		if (input.length != 16) {
			throw new IllegalArgumentException("I need a 128-bit key");
		}

		int[] key = new int[8];
		for (int j = 0; j < 8; j++) {
			key[-j+7] = (Byte.toUnsignedInt(input[2*j]) << 8) | (Byte.toUnsignedInt(input[2*j+1]));
		}

		for (int j = 0; j < 8; j++) {
			if (j%2 == 0) {
				X[j] = key[(j+1) % 8] << 16 | key[j];
				C[j] = key[(j+4) % 8] << 16 | key[(j+5) % 8];
			}
			else {
				X[j] = key[(j+5) % 8] << 16 | key[(j+4) % 8];
				C[j] = key[j] << 16 | key[(j+1) % 8];
			}
		}

		nextState();
		nextState();
		nextState();
		nextState();

		for (int j = 0; j < 8; j++) {
			C[j] = C[j] ^ X[(j+4) % 8];
		}

		if (DEBUG) {
			System.out.println("After key setup:");
			printX();
			printC();
		}
	}

	public void setupIV(byte[] input) {
		if (input.length != 8) {
			throw new IllegalArgumentException("I need a 64-bit iv");
		}

		int[] iv = new int[4];
		for (int j = 0; j < 4; j++) {
			iv[3-j] = (Byte.toUnsignedInt(input[2*j]) << 8) | (Byte.toUnsignedInt(input[2*j+1]));
		}
		for (int j = 0; j < 8; j++) {
			C[j] ^= iv[j%4 == 1 ? 3 : (9-j)%4] << 16 | iv[j%4 == 3 ? 0 : j%4] & 0xFFFF;
		}

		nextState();
		nextState();
		nextState();
		nextState();

		if (DEBUG) {
			System.out.println("After iv setup:");
			printX();
			printC();
		}
	}

	private void nextState() {
		updateCounter();

		int G[] = new int[8];
		for(int j = 0; j < 8; j++) {
			long t = X[j] + C[j] & 0xFFFFFFFFL;
			G[j] = (int)(((t * t) ^ ((t * t) >> 32)) % MAX_UNSIGNED_INT);
		}

		for (int j = 0; j< 8; j++) {
			int j1 = (((j-1) % 8) + 8) % 8;
			int j2 = (((j-2) % 8) + 8) % 8;

			if (j%2 == 0) {
				X[j] = G[j] + rotl(G[j1], 16) + rotl(G[j2], 16);
			}
			else {
				X[j] = G[j] + rotl(G[j1], 8) + G[j2];
			}
		}
	}

	private void updateCounter() {
		for (int j = 0; j < 8; j++) {
			long temp = (C[j] & 0xFFFFFFFFL) + (A[j] & 0xFFFFFFFFL) + b;
			b = (temp >= MAX_UNSIGNED_INT) ? (byte)1 : 0;
			C[j] = (int) (temp % MAX_UNSIGNED_INT);
		}
	}
	public void printX() {
		System.out.println("------");
		for (int i = 0; i < 8; i++) {
			System.out.println("X" + i + " = " + Integer.toHexString(X[i]));
		}
		System.out.println("------");
	}

	public void printC() {
		System.out.println("------");
		for (int i = 0; i < 8; i++) {
			System.out.println("C" + i + " = " + Integer.toHexString(C[i]));
		}
		System.out.println("------");
	}

	private static int rotl(int val, int pas) {
		return (val << pas) | (val >>> (32 - pas));
	}
}