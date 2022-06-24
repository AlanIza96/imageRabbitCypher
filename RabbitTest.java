import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class RabbitTest {

	public static void main(String[] args) {
		Rabbit r = new Rabbit();
		int i = 0;

		boolean error = false;
		
			r.reset();
			byte[] key = "0123456789012345".getBytes();
			byte[] iv = null;

			r.setupKey(key);
			if (iv != null) {
				r.setupIV(iv);
			}

			

			File fi = new File("gatito.png");
			byte[] fileContent;
			try {
				
				fileContent = Files.readAllBytes(fi.toPath());
				byte[] out = r.crypt(fileContent);
								
				System.out.println("\tINPUT: " + convertData(fileContent));
				System.out.println("\tout: " + convertData(out));

				Path pathEnc = Paths.get("encrypted.png");
				Files.write(pathEnc, out);

				r.reset();
				r.setupKey(key);
				byte[] decripted = r.crypt(out);
				System.out.println("\tdecripted: " + convertData(decripted));
				Path pathDec = Paths.get("decrypted.png");
				Files.write(pathDec, decripted);
			} catch (IOException e) {
				e.printStackTrace();
			}

		if (error) {
			System.out.println("Some tests failed.");
		}
	}

	private static byte[] convertData(String data) {
		if (data == null || data.length() == 0) {
			return null;
		}

		byte[] array = new byte[(data.length() + 1) / 3];
		int i = 0;
		for(String value : data.split(" ")) {
			array[i++] = (byte) (Integer.parseInt(value, 16) & 0xFF);
		}
		return array;
	}

	private static String convertData(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(" ");
			String hex = Integer.toHexString(Byte.toUnsignedInt(b));
			if (hex.length() == 1) {
				sb.append(" ");
			}
			sb.append(hex);
		}
		sb.deleteCharAt(0);
		return sb.toString();
	}
}