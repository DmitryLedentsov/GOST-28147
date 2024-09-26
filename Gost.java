import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class Gost {
    private static final int[][] blocks = {
        {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
        {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
        {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
        {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
        {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
        {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
        {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
        {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
    };
    
    private static final BigInteger key = new BigInteger("1831827938791238791");

    private static class Crypt {
        private BigInteger[] subkeys;
        private int[][] sbox;

        public Crypt(BigInteger key, int[][] sbox) {
            this.sbox = sbox;
            setKey(key);
        }

        private void setKey(BigInteger key) {
            this.subkeys = new BigInteger[8];
            for (int i = 0; i < 8; i++) {
                subkeys[i] = key.shiftRight(32 * i).and(BigInteger.valueOf(0xFFFFFFFFL));
            }
        }

        private BigInteger f(BigInteger part, BigInteger key) {
            BigInteger temp = part.xor(key);
            BigInteger output = BigInteger.ZERO;
            for (int i = 0; i < 8; i++) {
                int sboxIndex = temp.shiftRight(4 * i).and(BigInteger.valueOf(0b1111)).intValue();
                output = output.or(BigInteger.valueOf(sbox[i][sboxIndex]).shiftLeft(4 * i));
            }
            return output.shiftRight(11).or(output.shiftLeft(32 - 11)).and(BigInteger.valueOf(0xFFFFFFFFL));
        }

        public BigInteger encrypt(BigInteger msg) {
            BigInteger leftPart = msg.shiftRight(32);
            BigInteger rightPart = msg.and(BigInteger.valueOf(0xFFFFFFFFL));
            //System.out.println('\n');
          //
            //System.out.println("aa");
            for (int i = 0; i < 24; i++) {
                BigInteger temp = rightPart;
                rightPart = leftPart.xor(f(rightPart, subkeys[i % 8]));
                
                leftPart = temp;
                //System.out.print(i);
                //System.out.print(" ");
                //System.out.print(subkeys[i % 8]);
                //System.out.print(" ");
                //System.out.print(rightPart);
                //System.out.println(f(rightPart, subkeys[i % 8]).longValue());
            }

            for (int i = 0; i < 8; i++) {
                BigInteger temp = rightPart;
                rightPart = leftPart.xor(f(rightPart, subkeys[7 - i]));
                leftPart = temp;
            }
            //System.out.println('\n');
            //System.out.println(leftPart.longValue());
            //
            //System.out.println(rightPart.longValue());

            return leftPart.shiftLeft(32).or(rightPart);
        }

        public BigInteger decrypt(BigInteger cryptedMsg) {
            BigInteger leftPart = cryptedMsg.shiftRight(32);
            BigInteger rightPart = cryptedMsg.and(BigInteger.valueOf(0xFFFFFFFFL));

            for (int i = 0; i < 8; i++) {
                BigInteger temp = leftPart;
                leftPart = rightPart.xor(f(leftPart, subkeys[i]));
                rightPart = temp;
            }

            for (int i = 0; i < 24; i++) {
                BigInteger temp = leftPart;
                leftPart = rightPart.xor(f(leftPart, subkeys[7 - (i % 8)]));
                rightPart = temp;
            }

            return leftPart.shiftLeft(32).or(rightPart);
        }// Метод для шифрования текста с использованием Base64
        public String encryptText(String s) {
            byte[] inputBytes = s.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();

            for (int i = 0; i < inputBytes.length; i += 8) {
                byte[] block = new byte[8];
                int blockLength = Math.min(8, inputBytes.length - i);
                System.arraycopy(inputBytes, i, block, 0, blockLength);

                // Заполняем недостающие байты нулями, если длина блока меньше 8 байт
                BigInteger blockData = new BigInteger(1, block);
                BigInteger encryptedBlock = encrypt(blockData);

                // Добавляем зашифрованный блок в поток байтов
                byte[] encryptedBlockBytes = encryptedBlock.toByteArray();
                // Убираем лишние ведущие нули, если длина больше 8 байт
                if (encryptedBlockBytes.length > 8) {
                    encryptedBlockBytes = Arrays.copyOfRange(encryptedBlockBytes, encryptedBlockBytes.length - 8, encryptedBlockBytes.length);
                }
                encryptedStream.write(encryptedBlockBytes, 0, encryptedBlockBytes.length);
            }

            // Возвращаем закодированную строку в Base64
            return Base64.getEncoder().encodeToString(encryptedStream.toByteArray());
        }

        // Метод для расшифровки текста, закодированного в Base64
        public String decryptText(String s) {
            // Декодируем строку из Base64
            byte[] encryptedBytes = Base64.getDecoder().decode(s);
            ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();

            for (int i = 0; i < encryptedBytes.length; i += 8) {
                byte[] block = new byte[8];
                System.arraycopy(encryptedBytes, i, block, 0, 8);

                BigInteger encryptedBlock = new BigInteger(1, block);
                BigInteger decryptedBlock = decrypt(encryptedBlock);

                byte[] blockBytes = decryptedBlock.toByteArray();

                // Убираем ведущие нули, если длина массива больше 8 байт
                if (blockBytes.length > 8) {
                    blockBytes = Arrays.copyOfRange(blockBytes, blockBytes.length - 8, blockBytes.length);
                }

                decryptedStream.write(blockBytes, 0, blockBytes.length);
            }

            // Преобразуем результат в строку UTF-8
            return new String(decryptedStream.toByteArray(), StandardCharsets.UTF_8).trim();
        }
    }

    public static void main(String[] args) {
        Crypt gost = new Crypt(key, blocks);

        String originalText = "ABOBA 12345";
        System.out.println("Исходный текст: " + originalText);
        String encrypted = gost.encryptText(originalText);
        System.out.println("Зашифрованный текст (Base64): " + encrypted);

        String decrypted = gost.decryptText(encrypted);
        System.out.println("Расшифрованный текст: " + decrypted);

        System.out.println(decrypted.equals(originalText)? "ВСЕ ОК!!":"ТЕКСТ НЕ СОВПАДАЕТ, АХТУНГ!!!!");
    }

}

