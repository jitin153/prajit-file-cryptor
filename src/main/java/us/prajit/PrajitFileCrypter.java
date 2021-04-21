package us.prajit;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class PrajitFileCrypter {
	private static BlockingQueue<String> folders = new ArrayBlockingQueue<>(50);
	private static AtomicInteger filesAffected = new AtomicInteger(0);
	private static String key = "";
	private static boolean doForSubFoldersAsWell = false;
	private static String folderToBeCreated = "";
	private static String rootFolderPath = "";
	private static String operation = "";

	/*
	 * Constants
	 */
	private static final String ANSWER_YES = "Y";
	private static final String ANSWER_NO = "N";
	private static final String OPERATION_ENCRYPT = "E";
	private static final String OPERATION_DECRYPT = "D";
	private static final String ENCRYPTED_FILE_EXTENSION = "enc";
	private static final String FILENAME_APPEND_CHAR = "_";

	public static void main(String[] args) {
		try (Scanner scanner = new Scanner(System.in)) {
			System.out.println("Please enter folder path whose files to be encrypted/decrypted...");
			String inputFolderPath = scanner.nextLine();
			System.out.printf("Do you want to encrypt/decrypt files of sub folders as well? %s or %s%n", ANSWER_YES,
					ANSWER_NO);
			doForSubFoldersAsWell = scanner.nextLine().equalsIgnoreCase(ANSWER_YES);
			String outputFolderPath = "";
			if (doForSubFoldersAsWell) {
				System.out.printf(
						"Do you want to create separate folder in current working folder for encrypted/decrypted files? %s or %s%n",
						ANSWER_YES, ANSWER_NO);
				if (scanner.nextLine().equalsIgnoreCase(ANSWER_YES)) {
					System.out.println("Please enter the folder name you want to create...");
					folderToBeCreated = scanner.nextLine();
				} else {
					System.out.printf(
							"Do you want to collect all folders containg encrypted/decrypted files into single folder? %s or %s%n",
							ANSWER_YES, ANSWER_NO);
					if (scanner.nextLine().equalsIgnoreCase(ANSWER_YES)) {
						System.out.println("Please enter the folder path...");
						rootFolderPath = scanner.nextLine();
					}else {
						System.out.println("There are no other options available. Exiting program...");
						System.exit(0);
					}
				}
			} else {
				System.out.printf("Do you want to place encrypted/decrypted files into the same folder? %s or %s%n",
						ANSWER_YES, ANSWER_NO);
				String isIntoSameFolder = scanner.nextLine();
				if (isIntoSameFolder.equalsIgnoreCase(ANSWER_YES)) {
					outputFolderPath = inputFolderPath;
				} else {
					System.out
							.println("Please enter output folder path where encrypted/decrypted files to be stored...");
					outputFolderPath = scanner.nextLine();
				}
			}
			System.out.printf("Operation: Please type %s for encryption & %s for decryption...%n", OPERATION_ENCRYPT,
					OPERATION_DECRYPT);
			operation = scanner.nextLine();
			System.out.println("Please enter the key...");
			key = scanner.nextLine();
			long startTime = System.currentTimeMillis();
			if (doForSubFoldersAsWell) {
				listFolder(new File(inputFolderPath));
				if (!folders.contains(inputFolderPath)) {
					folders.put(inputFolderPath);
				}
				int availableProcessors = Runtime.getRuntime().availableProcessors();
				int numberOfFolders = folders.size();
				availableProcessors = availableProcessors <= numberOfFolders ? availableProcessors : numberOfFolders;
				System.out.println("Operation started, please wait...");
				while (!folders.isEmpty()) {
					CountDownLatch latch = new CountDownLatch(availableProcessors);
					for (int processor = 1; processor <= availableProcessors; processor++) {
						new Thread(new EncryptionWorker(folders, latch)).start();
					}
					latch.await();
				}
			} else {
				File outputFolder = new File(outputFolderPath);
				if (!outputFolder.exists()) {
					outputFolder.mkdirs();
				}
				for (final File fileEntry : new File(inputFolderPath).listFiles()) {
					if (fileEntry.isFile()) {
						doCrypto(fileEntry, operation, key, outputFolderPath);
					}
				}
			}
			long endTime = System.currentTimeMillis();
			System.out.println("Operation has been successfully done in " + (endTime - startTime) + " ms.");
		} catch (Exception e) {
			System.out.println(e);
		}
	}

	/*
	 * Recursive method to list all folder and sub folders
	 */
	public static void listFolder(final File inputFolderPath) {
		for (final File fileEntry : inputFolderPath.listFiles()) {
			if (fileEntry.isDirectory()) {
				try {
					folders.put(fileEntry.getPath());
				} catch (InterruptedException e) {
					System.out.println(e);
				}
				listFolder(fileEntry);
			}
		}
	}

	/*
	 * Worker thread class
	 */
	private static class EncryptionWorker implements Runnable {
		private BlockingQueue<String> folders;
		private CountDownLatch latch;

		public EncryptionWorker(BlockingQueue<String> folders, CountDownLatch latch) {
			this.folders = folders;
			this.latch = latch;
		}

		@Override
		public void run() {
			if (!folders.isEmpty()) {
				String folder = "";
				try {
					folder = folders.take();
				} catch (InterruptedException e) {
					System.out.println(e);
				}
				String outputDir = folder;
				File newFolder = null;
				if (!folderToBeCreated.isBlank() || !rootFolderPath.isBlank()) {
					if (!rootFolderPath.isBlank()) {
						String splitChar = "/";
						if (folder.contains("\\")) {
							splitChar = "\\";
						}
						String folderNames[] = folder.split(Pattern.quote(splitChar));
						String lastChildFolder = folderNames[folderNames.length - 1];
						outputDir = rootFolderPath + splitChar + lastChildFolder;
					} else if (!folderToBeCreated.isBlank()) {
						outputDir = folder + "/" + folderToBeCreated;
					}
					newFolder = new File(outputDir);
					if (!newFolder.exists()) {
						newFolder.mkdirs();
					}
				}
				for (final File fileEntry : new File(folder).listFiles()) {

					if (fileEntry.isFile()) {
						doCrypto(fileEntry, operation, key, outputDir);
					}
				}
				if ((!folderToBeCreated.isBlank() || !rootFolderPath.isBlank()) && newFolder.exists()
						&& filesAffected.get() < 1) {
					newFolder.delete();
				}
			}
			latch.countDown();
		}
	}

	private static void doCrypto(File fileEntry, String operation, String key, String outputFolderPath) {
		String fileName = fileEntry.getName();
		String fileNameOnly = fileName.substring(0, fileName.lastIndexOf('.'));
		String originalFileExtension = "";
		try {
			originalFileExtension = fileName.substring(fileName.lastIndexOf('.') + 1);
			if (operation.equalsIgnoreCase(OPERATION_ENCRYPT)) {
				String outputFilePath = new StringBuilder(outputFolderPath).append("/").append(fileNameOnly)
						.append(FILENAME_APPEND_CHAR).append(originalFileExtension).append(".")
						.append(ENCRYPTED_FILE_EXTENSION).toString();
				FileCryptUtil.encryptFile(key, fileEntry.getPath(), outputFilePath);
				filesAffected.incrementAndGet();
			} else if (operation.equalsIgnoreCase(OPERATION_DECRYPT)
					&& originalFileExtension.equalsIgnoreCase(ENCRYPTED_FILE_EXTENSION)) {
				fileNameOnly = fileNameOnly.substring(0, fileNameOnly.lastIndexOf('_'));
				originalFileExtension = fileName.substring(fileName.lastIndexOf('_') + 1, fileName.lastIndexOf('.'));
				FileCryptUtil.decryptFile(key, fileEntry.getPath(),
						outputFolderPath + "/" + fileNameOnly + "." + originalFileExtension);
				filesAffected.incrementAndGet();
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			System.out.println(e);
		}
	}

	/*
	 * Utility class to do the actual encryption/decryption.
	 */
	private static class FileCryptUtil {

		private static final String ALGORITHM = "AES";

		public static void encryptFile(String secret, String inputFilePath, String outputFilePath)
				throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
				BadPaddingException, IOException {
			doCrypto(Cipher.ENCRYPT_MODE, secret, inputFilePath, outputFilePath);
		}

		public static void decryptFile(String secret, String inputFilePath, String outputFilePath)
				throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
				BadPaddingException, IOException {
			doCrypto(Cipher.DECRYPT_MODE, secret, inputFilePath, outputFilePath);
		}

		private static void doCrypto(int cipherMode, String secret, String inputFilePath, String outputFilePath)
				throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
				BadPaddingException, IOException {
			SecretKeySpec key = new SecretKeySpec(secret.getBytes(), ALGORITHM);
			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(cipherMode, key);
			try (InputStream inputStream = new FileInputStream(new File(inputFilePath));
					OutputStream outputStream = new FileOutputStream(new File(outputFilePath))) {
				outputStream.write(cipher.doFinal(inputStream.readAllBytes()));
			} catch (IOException e) {
				System.out.println(e);
				throw new IOException(e);
			}
		}
	}

}
