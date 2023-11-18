package encryptionutils;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

/**
 * This class provides methods to encrypt and decrypt text using the AES (Advanced Encryption Standard) algorithm.
 * Users can choose between the CBC (Cipher Block Chaining) and GCM (Galois/Counter Mode) modes of operation.
 */
public class AESEncryption {
    private static final String AES_ALGORITHM = "AES";
    private static final String CBC_MODE = "CBC";
    private static final String GCM_MODE = "GCM";

    /**
     * Encrypts the given text using the AES algorithm with the specified mode of operation.
     *
     * @param text The text to be encrypted.
     * @param key The encryption key. It should be a 128-bit, 192-bit, or 256-bit key.
     * @param mode The mode of operation. Valid values are "CBC" and "GCM".
     * @return Returns the encrypted text.
     * @throws NoSuchAlgorithmException if the AES algorithm is not available.
     * @throws NoSuchPaddingException if the requested padding mechanism is not available.
     * @throws InvalidKeyException if the encryption key is invalid.
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid.
     * @throws IllegalBlockSizeException if the block size is invalid.
     * @throws BadPaddingException if the padding is invalid.
     */
    public static String encrypt(String text, String key, String mode) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + mode + "/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);

        if (mode.equals(CBC_MODE)) {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        } else if (mode.equals(GCM_MODE)) {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, key.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        } else {
            throw new IllegalArgumentException("Invalid mode of operation. Valid values are 'CBC' and 'GCM'.");
        }

        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts the given encrypted text using the AES algorithm with the specified mode of operation.
     *
     * @param encryptedText The encrypted text to be decrypted.
     * @param key The encryption key. It should be a 128-bit, 192-bit, or 256-bit key.
     * @param mode The mode of operation. Valid values are "CBC" and "GCM".
     * @return Returns the decrypted text.
     * @throws NoSuchAlgorithmException if the AES algorithm is not available.
     * @throws NoSuchPaddingException if the requested padding mechanism is not available.
     * @throws InvalidKeyException if the encryption key is invalid.
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid.
     * @throws IllegalBlockSizeException if the block size is invalid.
     * @throws BadPaddingException if the padding is invalid.
     */
    public static String decrypt(String encryptedText, String key, String mode) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM + "/" + mode + "/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), AES_ALGORITHM);

        if (mode.equals(CBC_MODE)) {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        } else if (mode.equals(GCM_MODE)) {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, key.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        } else {
            throw new IllegalArgumentException("Invalid mode of operation. Valid values are 'CBC' and 'GCM'.");
        }

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
}

// Usage Example for AESEncryption

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AESEncryptionGUI extends JFrame {
    private JTextField textField;
    private JTextArea textArea;
    private JComboBox<String> modeComboBox;
    private JButton encryptButton;
    private JButton decryptButton;

    public AESEncryptionGUI() {
        setTitle("AES Encryption");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel inputPanel = new JPanel(new FlowLayout());
        JLabel label = new JLabel("Enter Text:");
        textField = new JTextField(20);
        inputPanel.add(label);
        inputPanel.add(textField);

        JPanel modePanel = new JPanel(new FlowLayout());
        JLabel modeLabel = new JLabel("Mode:");
        String[] modes = {"CBC", "GCM"};
        modeComboBox = new JComboBox<>(modes);
        modePanel.add(modeLabel);
        modePanel.add(modeComboBox);

        JPanel buttonPanel = new JPanel(new FlowLayout());
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        JPanel outputPanel = new JPanel(new FlowLayout());
        JLabel outputLabel = new JLabel("Output:");
        textArea = new JTextArea(10, 30);
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        outputPanel.add(outputLabel);
        outputPanel.add(scrollPane);

        add(inputPanel, BorderLayout.NORTH);
        add(modePanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
        add(outputPanel, BorderLayout.EAST);

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String text = textField.getText();
                String key = "MySecretKey12345"; // Replace with your own encryption key
                String mode = (String) modeComboBox.getSelectedItem();

                try {
                    String encryptedText = AESEncryption.encrypt(text, key, mode);
                    textArea.setText(encryptedText);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AESEncryptionGUI.this, "Encryption failed: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String encryptedText = textField.getText();
                String key = "MySecretKey12345"; // Replace with your own encryption key
                String mode = (String) modeComboBox.getSelectedItem();

                try {
                    String decryptedText = AESEncryption.decrypt(encryptedText, key, mode);
                    textArea.setText(decryptedText);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AESEncryptionGUI.this, "Decryption failed: " + ex.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new AESEncryptionGUI();
            }
        });
    }
}
